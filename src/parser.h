#pragma once
#include <iostream>
#include <cstdint>
#include <vector>
#include <functional>

struct _vinstr_meta
{
	std::string name;

	bool has_imm;
	std::uintptr_t imm;
};

using callback_t = std::function<bool(_vinstr_meta*)>;

// this singleton class contains all the 
// information for parsed virtual instructions...
class parse_t
{
public:
	static auto get_instance() -> parse_t*;
	void add_vinstr(std::string vinstr_name);
	void add_vinstr(std::string vinstr_name, std::uintptr_t imm_val);
	bool for_each(callback_t callback);
private:
	parse_t();
	std::vector<_vinstr_meta> vinstrs;
};