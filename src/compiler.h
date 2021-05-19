#pragma once
#include <Windows.h>
#include <vmprofiler.hpp>
#include <vmctx.h>
#include <vm.h>
#include <algorithm>
#include "parser.h"

#define NT_HEADER(x) \
	reinterpret_cast<PIMAGE_NT_HEADERS64>( \
		reinterpret_cast<PIMAGE_DOS_HEADER>(x)->e_lfanew + x)

namespace vm
{
	 struct base_data_t 
	 {
		 std::uintptr_t module_base; 
		 std::uintptr_t image_base;
	 };

	struct vinstr_data
	{
		std::uint8_t vm_handler;
		std::uint64_t operand;
		std::uint8_t imm_size; // size in bits...
	};

	class compiler_t
	{
	public:
		explicit compiler_t(
			base_data_t base_data,
			vmp2::exec_type_t exec_type, 
			std::vector<vm::handler_t>* vm_handlers,
			zydis_routine_t* calc_jmp
		);

		std::pair<bool, std::vector<vinstr_data>*> encode();
		std::pair<std::uint64_t, std::vector<std::uint8_t>* > encrypt();
	private:
		transform::map_t calc_jmp_transforms;
		zydis_routine_t* calc_jmp;
		std::vector<vm::handler_t>* vm_handlers;
		vmp2::exec_type_t exec_type;
		std::vector<vinstr_data> vinstrs;
		std::vector<std::uint8_t> result_buffer;
		std::uintptr_t image_base, module_base;
	};
}