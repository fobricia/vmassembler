#include "parser.h"

parse_t::parse_t() 
{}

auto parse_t::get_instance() -> parse_t*
{
	static parse_t obj;
	return &obj;
}

void parse_t::add_vinstr(std::string vinstr_name)
{
	_vinstr_meta data{ vinstr_name, false, 0u };
	vinstrs.push_back(data);
}

void parse_t::add_vinstr(std::string vinstr_name, std::uintptr_t imm_val)
{
	_vinstr_meta data{ vinstr_name, true, imm_val };
	vinstrs.push_back(data);
}

bool parse_t::for_each(callback_t callback)
{
	for (auto& entry : vinstrs)
		if (!callback(&entry))
			return false;

	return true;
}