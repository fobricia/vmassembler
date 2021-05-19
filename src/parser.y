%{
#include <stdlib.h>
#include "parser.h"
int yylex(void);
void yyerror(char *);
extern int yylineno;
%}


%union {
char vinstr_name[20];
unsigned long long imm_val;
}

%token <vinstr_name> VINSTR
%token <imm_val> IMM

%%
PROGRAM:
	VINSTR					{ parse_t::get_instance()->add_vinstr($1); }
	| VINSTR IMM			{ parse_t::get_instance()->add_vinstr($1, $2); }
	| PROGRAM VINSTR		{ parse_t::get_instance()->add_vinstr($2); }
	| PROGRAM VINSTR IMM	{ parse_t::get_instance()->add_vinstr($2, $3); }
	;
%%