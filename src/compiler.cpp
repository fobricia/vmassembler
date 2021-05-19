#include "compiler.h"

namespace vm
{
	compiler_t::compiler_t(
		base_data_t base_data,
		vmp2::exec_type_t exec_type,
		std::vector<vm::handler_t>* vm_handlers,
		zydis_routine_t* calc_jmp
	)
		: module_base(base_data.module_base),
		image_base(base_data.image_base),
		exec_type(exec_type),
		vm_handlers(vm_handlers),
		calc_jmp(calc_jmp)
	{
		if (!parse_t::get_instance()->for_each(
			[&](_vinstr_meta* vinstr) -> bool
			{
				std::printf("> vinstr name = %s, has imm = %d, imm = 0x%p\n",
					vinstr->name.c_str(), vinstr->has_imm, vinstr->imm);

				for (auto& vm_handler : *vm_handlers)
					if (vm_handler.profile && vm_handler.profile->name == vinstr->name)
						return true;

				std::printf("> this vm protected file does not have the vm handler for: %s...\n",
					vinstr->name.c_str());

				return false;
			}
		))
		{
			std::printf("[!] binary does not have the required vm handlers...\n");
			exit(-1);
		}

		if(!vm::handler::get_operand_transforms(*calc_jmp, calc_jmp_transforms))
		{
			std::printf("[!] failed to extract calc_jmp transformations...\n");
			exit(-1);
		}
	}

	std::pair<bool, std::vector<vinstr_data>*> compiler_t::encode()
	{
		parse_t::get_instance()->for_each(
			[&](_vinstr_meta* vinstr) -> bool
			{
				for (auto itr = vm_handlers->begin(); itr != vm_handlers->end(); ++itr)
				{
					if (itr->profile && itr->profile->name == vinstr->name)
					{
						vinstrs.push_back({ (std::uint8_t)(itr - vm_handlers->begin()),
							vinstr->imm, itr->profile->imm_size });
						break;
					}
				}
				return true;
			}
		);

		return { true, &vinstrs };
	}

	std::pair<std::uint64_t, std::vector<std::uint8_t>*> compiler_t::encrypt()
	{
		const auto end_of_module = 
			NT_HEADER(module_base)->OptionalHeader.SizeOfImage + image_base;

		//
		// init decryption key...
		//

		// decryption key starts off as the image 
		// base address of the virtual instructions...
		std::uintptr_t decrypt_key = end_of_module, start_addr;
		if (exec_type == vmp2::exec_type_t::backward)
		{
			std::for_each(vinstrs.begin(), vinstrs.end(),
				[&](const vinstr_data& vinstr)
				{
					(++decrypt_key) += 
						vinstr.imm_size ? vinstr.imm_size / 8 : 0;
				}
			);
		}
		start_addr = decrypt_key;

		//
		// invert the encoded virtual instructions operands if vip advances backward...
		//

		if (exec_type == vmp2::exec_type_t::backward)
			std::reverse(vinstrs.begin(), vinstrs.end());

		//
		// loop over the instructions and encrypt them... 
		//

		for (auto& vinstr : vinstrs)
		{
			std::printf("> decrypt key = 0x%p\n", decrypt_key);

			auto vm_handler_idx = vinstr.vm_handler;
			std::tie(vinstr.vm_handler, decrypt_key) = 
				vm::encrypt_operand(calc_jmp_transforms,
					vinstr.vm_handler, decrypt_key);

			if (!vinstr.imm_size)
			{
				result_buffer.push_back(vinstr.vm_handler);
				continue;
			}

			auto transforms = vm_handlers->at(vm_handler_idx).transforms;
			std::tie(vinstr.operand, decrypt_key) =
				vm::encrypt_operand(transforms, vinstr.operand, decrypt_key);

			//
			// operands must be backwards if VIP advances backward...
			//

			if (exec_type == vmp2::exec_type_t::backward)
			{
				for (auto idx = 0u; idx < vinstr.imm_size / 8; ++idx)
					result_buffer.push_back(
						reinterpret_cast<std::uint8_t*>(&vinstr.operand)[idx]);

				result_buffer.push_back(vinstr.vm_handler);
			}
			else
			{
				result_buffer.push_back(vinstr.vm_handler);

				for (auto idx = 0u; idx < vinstr.imm_size / 8; ++idx)
					result_buffer.push_back(
						reinterpret_cast<std::uint8_t*>(&vinstr.operand)[idx]);
			}
		}

		return { start_addr, &result_buffer };
	}
}