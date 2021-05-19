#include <iostream>
#include <sstream>
#include <Windows.h>
#include <fstream>
#include <transform.hpp>

#include "compiler.h"
#include "parser.tab.h"
#include "parser.h"
#include "cli-parser.hpp"
#include "vmasm.hpp"

extern FILE* yyin;
extern "C" int yywrap()
{ return 1; }

void yyerror(char* msg)
{ std::printf("[!] parsing failure: %s\n", msg); }

int __cdecl main(int argc, const char* argv[])
{
	//
	// handle arguments from the commandline...
	//

	argparse::argument_parser_t argp(
		"vmassembler", "virtual instruction assembler for VMProtect 2");

	argp.add_argument()
		.names({ "--input", "--in" })
		.description("path to a vasm file to be assembled...")
		.required(true);

	argp.add_argument()
		.names({ "--vmpbin", "--bin" })
		.description("path to protected binary...")
		.required(true);

	argp.add_argument()
		.names({ "--vmentry", "--entry" })
		.description("rva to vm entry...")
		.required(true);

	argp.add_argument()
		.names({ "--imagebase", "--base" })
		.description("optional header image base field value...")
		.required(true);

	argp.add_argument()
		.name({ "--advancement" })
		.description("which direction vip advances... the options are 'forward' and 'backward'")
		.required(true);

	argp.add_argument()
		.name({ "--output" })
		.description("output file name and path...")
		.required(true);

	argp.enable_help();
	auto err = argp.parse(argc, argv);

	if (err)
	{
		std::cout << err << std::endl;
		return -1;
	}

	if (argp.exists("help"))
	{
		argp.print_help();
		return 0;
	}

	//
	// set yyin to the vasm file...
	//

	if ((yyin = fopen(argp.get<std::string>("input").c_str(), "r")) == nullptr)
	{
		std::printf("[!] failed to open vasm file...\n");
		return -1;
	}

	//
	// parse vasm file for all of the instructions...
	//

	yyparse();
	std::printf("[+] finished parsing vasm file...\n");

	//
	// init vm variables...
	//

	const auto module_base = 
		reinterpret_cast<std::uintptr_t>(
			LoadLibraryExA(argp.get<std::string>("vmpbin").c_str(),
				NULL, DONT_RESOLVE_DLL_REFERENCES));

	const auto vm_entry_rva = std::strtoull(
		argp.get<std::string>("vmentry").c_str(), nullptr, 16);

	const auto image_base = std::strtoull(
		argp.get<std::string>("imagebase").c_str(), nullptr, 16);

	vmp2::exec_type_t advancement = 
		argp.get<std::string>("advancement") == "backward" ? 
			vmp2::exec_type_t::backward : vmp2::exec_type_t::forward;

	zydis_routine_t vm_entry, calc_jmp;
	std::vector<vm::handler_t> vm_handlers;
	std::uintptr_t* vm_handler_table;
	ZydisDecodedInstruction encrypt_rva;

	if (!vm::util::flatten(vm_entry, module_base + vm_entry_rva))
	{
		std::printf("[!] failed to flatten vm entry...\n");
		return -1;
	}

	std::printf("[+] flattened vm_entry...\n");
	vm::util::deobfuscate(vm_entry);
	std::printf("[+] deobfuscated vm_entry...\n");
	vm::util::print(vm_entry);

	if (!(vm_handler_table = vm::handler::table::get(vm_entry)))
	{
		std::printf("[!] failed to obtain vm handler table...\n");
		return -1;
	}

	if (!vm::handler::get_all(module_base, image_base, vm_entry, vm_handler_table, vm_handlers))
	{
		std::printf("[!] failed to get all vm handlers...\n");
		return -1;
	}

	if (!vm::get_calc_jmp(vm_entry, calc_jmp))
	{
		std::printf("[!] failed to get calc_jmp...\n");
		return -1;
	}

	if (!vm::get_vinstr_rva_transform(vm_entry, &encrypt_rva))
	{
		std::printf("[!] failed to get virtual instruction rva encryption transform...\n");
		return -1;
	}

	vm::compiler_t compiler({ module_base, image_base }, advancement, &vm_handlers, &calc_jmp);

	//
	// encode virtual instructions...
	//

	auto [encoded_success, vinstrs] = compiler.encode();
	std::printf("[+] finished encoding... encoded instructions below...\n");

	if (!encoded_success)
	{
		std::printf("[!] failed to encode virtual instructions...\n");
		return -1;
	}

	for (auto& vinstr : *vinstrs)
	{
		if (vinstr.imm_size)
			std::printf("> 0x%x - 0x%x\n", vinstr.vm_handler, vinstr.operand);
		else
			std::printf("> 0x%x\n", vinstr.vm_handler);
	}

	//
	// encrypt virtual instructions...
	//

	auto [entry_rva, result_buffer] = compiler.encrypt();
	std::printf("[+] finished encrypting... encrypted instructions below...\n");

	if (!entry_rva)
	{
		std::printf("[!] failed to encrypt virtual instructions...\n");
		return -1;
	}

	std::printf("> virtual instructions must be allocated at = 0x%p\n", entry_rva);
	std::printf("> ");
	{
		auto idx = 0u;
		for (auto byte : *result_buffer)
		{
			std::printf("0x%x ", byte);
			if (++idx == 10)
			{
				std::printf("\n");
				idx = 0u;
			}
		}
	}
	std::printf("\n");

	//
	// write the result to disk...
	//

	vmasm::file_header_t file_header;
	file_header.magic = VASM_MAGIC;
	file_header.epoch_time = std::time(nullptr);
	file_header.vasm_size = result_buffer->size();
	file_header.alloc_rva = (entry_rva - image_base);
	file_header.vasm_offset = sizeof vmasm::file_header_t;
	file_header.encrypted_rva = vm::transform::apply(
		encrypt_rva.operands[0].size,
		encrypt_rva.mnemonic, entry_rva,
		// check to see if this instruction has an IMM...
		vm::transform::has_imm(&encrypt_rva) ?
		encrypt_rva.operands[1].imm.value.u : 0);

	std::ofstream output(argp.get<std::string>("output"), std::ios::binary);
	output.write(reinterpret_cast<char*>(&file_header), sizeof file_header);
	output.write(reinterpret_cast<char*>(result_buffer->data()), result_buffer->size());
	output.close();
}