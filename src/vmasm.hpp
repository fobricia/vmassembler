#pragma once
#include <cstdint>
#define VASM_MAGIC 'MSAV'

namespace vmasm
{
	enum class version_t
	{
		v1
	};

	struct file_header_t
	{
		std::uint32_t magic; // VASM
		version_t version;
		std::uint64_t epoch_time;
		std::uint64_t alloc_rva; 
		std::uint64_t encrypted_rva;
		std::uint32_t vasm_size;
		std::uint32_t vasm_offset;
	};
}