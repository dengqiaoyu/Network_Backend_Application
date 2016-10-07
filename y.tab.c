#ifndef lint
static const char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif

#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYPATCH 20130304

#define YYEMPTY        (-1)
#define yyclearin      (yychar = YYEMPTY)
#define yyerrok        (yyerrflag = 0)
#define YYRECOVERING() (yyerrflag != 0)

#define YYPREFIX "yy"

#define YYPURE 0

#line 7 "parser.y"

#include "lisod.h"

#define SUCCESS 0
#define F_MELONG 1
#define F_URLONG 2
#define F_VELONG 3
#define F_HNLONG 4
#define F_HVLONG 5

/* Define YACCDEBUG to enable debug messages for this lex file */
/*#define YACCDEBUG*/
#define YYERROR_VERBOSE
#ifdef YACCDEBUG
#include <stdio.h>
#define YPRINTF(...) printf(__VA_ARGS__)
#else
#define YPRINTF(...)
#endif

/* yyparse() calls yyerror() on error */
void yyerror (char *s);

void set_parsing_options(char *buf, size_t siz, Requests *parsing_request);

/* yyparse() calls yylex() to get tokens */
extern int yylex();


/*
** Global variables required for parsing from buffer
** instead of stdin:
*/

/* Pointer to the buffer that contains input */
char *parsing_buf;

/* Current position in the buffer */
int parsing_offset;

/* Buffer size */
size_t parsing_buf_siz;

/* Current parsing_request Header Struct */
Requests *parsing_request;

#line 57 "parser.y"
#ifdef YYSTYPE
#undef  YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
#endif
#ifndef YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
typedef union {
    char str[8192];
    int i;
} YYSTYPE;
#endif /* !YYSTYPE_IS_DECLARED */
#line 78 "y.tab.c"

/* compatibility with bison */
#ifdef YYPARSE_PARAM
/* compatibility with FreeBSD */
# ifdef YYPARSE_PARAM_TYPE
#  define YYPARSE_DECL() yyparse(YYPARSE_PARAM_TYPE YYPARSE_PARAM)
# else
#  define YYPARSE_DECL() yyparse(void *YYPARSE_PARAM)
# endif
#else
# define YYPARSE_DECL() yyparse(void)
#endif

/* Parameters sent to lex. */
#ifdef YYLEX_PARAM
# define YYLEX_DECL() yylex(void *YYLEX_PARAM)
# define YYLEX yylex(YYLEX_PARAM)
#else
# define YYLEX_DECL() yylex(void)
# define YYLEX yylex()
#endif

/* Parameters sent to yyerror. */
#ifndef YYERROR_DECL
#define YYERROR_DECL() yyerror(const char *s)
#endif
#ifndef YYERROR_CALL
#define YYERROR_CALL(msg) yyerror(msg)
#endif

extern int YYPARSE_DECL();

#define t_crlf 257
#define t_backslash 258
#define t_digit 259
#define t_dot 260
#define t_token_char 261
#define t_lws 262
#define t_colon 263
#define t_separators 264
#define t_sp 265
#define t_ws 266
#define YYERRCODE 256
static const short yylhs[] = {                           -1,
    1,    1,    1,    4,    4,    2,    2,    2,    2,    5,
    5,    3,    3,    3,    6,    7,    7,    8,    0,    0,
    0,
};
static const short yylen[] = {                            2,
    1,    1,    1,    1,    2,    1,    1,    1,    1,    1,
    3,    0,    1,    1,    6,    0,    2,    7,    3,    2,
    0,
};
static const short yydefred[] = {                         0,
    2,    3,    1,    0,    4,    0,    0,    0,    5,   20,
    0,    9,    8,    7,    6,   10,    0,   19,    0,   17,
    0,   14,    0,   13,    0,    0,   11,    0,   15,    0,
    0,    0,   18,
};
static const short yydgoto[] = {                          4,
   15,   16,   23,    6,   17,    7,   11,   20,
};
static const short yysindex[] = {                      -243,
    0,    0,    0,    0,    0, -200, -254, -213,    0,    0,
 -193,    0,    0,    0,    0,    0, -203,    0, -222,    0,
 -213,    0, -213,    0, -258, -257,    0, -196,    0, -213,
 -196, -236,    0,
};
static const short yyrindex[] = {                        10,
    0,    0,    0,    0,    0,    0, -219,    0,    0,    0,
    0,    0,    0,    0,    0,    0, -206,    0, -244,    0,
    0,    0,    0,    0,    0, -206,    0, -206,    0,    0,
 -228,    0,    0,
};
static const short yygindex[] = {                         0,
    1,  -19,  -17,   15,  -15,    0,    0,    0,
};
#define YYTABLESIZE 70
static const short yytable[] = {                         29,
    5,   25,   10,   27,   28,   26,    9,   24,   22,   21,
   30,    5,   27,   32,   31,    1,    2,    3,   12,    9,
   33,   12,    1,    2,    3,   19,   13,   14,   12,   12,
   12,   12,   12,    0,   12,   12,    1,    2,    3,   16,
   16,   16,   24,   22,   12,    1,    2,    3,    0,   13,
   14,   12,   12,   12,   12,    0,   12,   12,    1,    2,
    3,   21,   22,   18,    8,    1,    2,    3,   24,   22,
};
static const short yycheck[] = {                        257,
    0,   19,  257,   23,  263,   21,    6,  265,  266,    0,
   28,   11,   32,   31,   30,  259,  260,  261,  263,   19,
  257,  258,  259,  260,  261,   11,  263,  264,  257,  258,
  259,  260,  261,   -1,  263,  264,  259,  260,  261,  259,
  260,  261,  265,  266,  258,  259,  260,  261,   -1,  263,
  264,  258,  259,  260,  261,   -1,  263,  264,  259,  260,
  261,  265,  266,  257,  265,  259,  260,  261,  265,  266,
};
#define YYFINAL 4
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 266
#if YYDEBUG
static const char *yyname[] = {

"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"t_crlf","t_backslash","t_digit",
"t_dot","t_token_char","t_lws","t_colon","t_separators","t_sp","t_ws",
};
static const char *yyrule[] = {
"$accept : request",
"allowed_char_for_token : t_token_char",
"allowed_char_for_token : t_digit",
"allowed_char_for_token : t_dot",
"token : allowed_char_for_token",
"token : token allowed_char_for_token",
"allowed_char_for_text : allowed_char_for_token",
"allowed_char_for_text : t_separators",
"allowed_char_for_text : t_colon",
"allowed_char_for_text : t_backslash",
"text : allowed_char_for_text",
"text : text ows allowed_char_for_text",
"ows :",
"ows : t_sp",
"ows : t_ws",
"request_line : token t_sp text t_sp text t_crlf",
"request_headers :",
"request_headers : request_headers request_header",
"request_header : token ows t_colon ows text ows t_crlf",
"request : request_line request_headers t_crlf",
"request : request_line t_crlf",
"request :",

};
#endif

int      yydebug;
int      yynerrs;

int      yyerrflag;
int      yychar;
YYSTYPE  yyval;
YYSTYPE  yylval;

/* define the initial stack-sizes */
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH  YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH  500
#endif
#endif

#define YYINITSTACKSIZE 500

typedef struct {
    unsigned stacksize;
    short    *s_base;
    short    *s_mark;
    short    *s_last;
    YYSTYPE  *l_base;
    YYSTYPE  *l_mark;
} YYSTACKDATA;
/* variables for the parser stack */
static YYSTACKDATA yystack;
#line 256 "parser.y"


/* C code */

void set_parsing_options(char *buf, size_t siz, Requests *request)
{
    parsing_buf = buf;
    parsing_offset = 0;
    parsing_buf_siz = siz;
    parsing_request = request;
}

void yyerror (char *s) {fprintf (stderr, "%s\n", s);}
#line 266 "y.tab.c"

#if YYDEBUG
#include <stdio.h>		/* needed for printf */
#endif

#include <stdlib.h>	/* needed for malloc, etc */
#include <string.h>	/* needed for memset */

/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(YYSTACKDATA *data)
{
    int i;
    unsigned newsize;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = data->stacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = (int) (data->s_mark - data->s_base);
    newss = (short *)realloc(data->s_base, newsize * sizeof(*newss));
    if (newss == 0)
        return -1;

    data->s_base = newss;
    data->s_mark = newss + i;

    newvs = (YYSTYPE *)realloc(data->l_base, newsize * sizeof(*newvs));
    if (newvs == 0)
        return -1;

    data->l_base = newvs;
    data->l_mark = newvs + i;

    data->stacksize = newsize;
    data->s_last = data->s_base + newsize - 1;
    return 0;
}

#if YYPURE || defined(YY_NO_LEAKS)
static void yyfreestack(YYSTACKDATA *data)
{
    free(data->s_base);
    free(data->l_base);
    memset(data, 0, sizeof(*data));
}
#else
#define yyfreestack(data) /* nothing */
#endif

#define YYABORT  goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR  goto yyerrlab

int
YYPARSE_DECL()
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")) != 0)
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = YYEMPTY;
    yystate = 0;

#if YYPURE
    memset(&yystack, 0, sizeof(yystack));
#endif

    if (yystack.s_base == NULL && yygrowstack(&yystack)) goto yyoverflow;
    yystack.s_mark = yystack.s_base;
    yystack.l_mark = yystack.l_base;
    yystate = 0;
    *yystack.s_mark = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = YYLEX) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
        {
            goto yyoverflow;
        }
        yystate = yytable[yyn];
        *++yystack.s_mark = yytable[yyn];
        *++yystack.l_mark = yylval;
        yychar = YYEMPTY;
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;

    yyerror("syntax error");

    goto yyerrlab;

yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yystack.s_mark]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yystack.s_mark, yytable[yyn]);
#endif
                if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
                {
                    goto yyoverflow;
                }
                yystate = yytable[yyn];
                *++yystack.s_mark = yytable[yyn];
                *++yystack.l_mark = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yystack.s_mark);
#endif
                if (yystack.s_mark <= yystack.s_base) goto yyabort;
                --yystack.s_mark;
                --yystack.l_mark;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = YYEMPTY;
        goto yyloop;
    }

yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yystack.l_mark[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 2:
#line 117 "parser.y"
	{
    yyval.i = '0' + yystack.l_mark[0].i;
}
break;
case 4:
#line 126 "parser.y"
	{
    YPRINTF("token: Matched rule 1.\n");
    snprintf(yyval.str, 8192, "%c", yystack.l_mark[0].i);
}
break;
case 5:
#line 130 "parser.y"
	{
    YPRINTF("token: Matched rule 2.\n");
  snprintf(yyval.str, 8192, "%s%c", yystack.l_mark[-1].str, yystack.l_mark[0].i);
}
break;
case 7:
#line 157 "parser.y"
	{
    yyval.i = yystack.l_mark[0].i;
}
break;
case 8:
#line 160 "parser.y"
	{
    yyval.i = yystack.l_mark[0].i;
}
break;
case 9:
#line 163 "parser.y"
	{
    yyval.i = yystack.l_mark[0].i;
}
break;
case 10:
#line 171 "parser.y"
	{
    YPRINTF("text: Matched rule 1.\n");
    snprintf(yyval.str, 8192, "%c", yystack.l_mark[0].i);
}
break;
case 11:
#line 175 "parser.y"
	{
    YPRINTF("text: Matched rule 2.\n");
    snprintf(yyval.str, 8192, "%s%s%c", yystack.l_mark[-2].str, yystack.l_mark[-1].str, yystack.l_mark[0].i);
}
break;
case 12:
#line 183 "parser.y"
	{
    YPRINTF("OWS: Matched rule 1\n");
    yyval.str[0]=0;
}
break;
case 13:
#line 187 "parser.y"
	{
    YPRINTF("OWS: Matched rule 2\n");
    snprintf(yyval.str, 8192, "%c", yystack.l_mark[0].i);
}
break;
case 14:
#line 191 "parser.y"
	{
    YPRINTF("OWS: Matched rule 3\n");
    snprintf(yyval.str, 8192, "%s", yystack.l_mark[0].str);
}
break;
case 15:
#line 196 "parser.y"
	{
    YPRINTF("request_Line:\n%s\n%s\n%s\n",yystack.l_mark[-5].str, yystack.l_mark[-3].str, yystack.l_mark[-1].str);
    if (strlen(yystack.l_mark[-5].str) > MAX_SIZE_S) {
        return F_MELONG;
    }
    else if (strlen(yystack.l_mark[-3].str) > MAX_SIZE) {
        return F_URLONG;
    }
    else if (strlen(yystack.l_mark[-1].str) > MAX_SIZE_S) {
        return F_VELONG;
    }
        
    strncpy(parsing_request->http_method, yystack.l_mark[-5].str, MAX_SIZE_S);
    strncpy(parsing_request->http_uri, yystack.l_mark[-3].str, MAX_SIZE);
    strncpy(parsing_request->http_version, yystack.l_mark[-1].str, MAX_SIZE_S);
}
break;
case 18:
#line 217 "parser.y"
	{
    YPRINTF("request_Header:%s: %s\n", yystack.l_mark[-6].str, yystack.l_mark[-2].str);
    int index = parsing_request->h_count;
    if (strlen(yystack.l_mark[-6].str) > MAX_SIZE) {
        return F_HNLONG;
    }
    else if (strlen(yystack.l_mark[-2].str) > MAX_SIZE) {
        return F_HVLONG;
    }

    strncpy(parsing_request->headers[index].h_name, yystack.l_mark[-6].str, MAX_SIZE);
    strncpy(parsing_request->headers[index].h_value, yystack.l_mark[-2].str, MAX_SIZE);
    index++;
    parsing_request->h_count = index;
    Request_header *new_headers = realloc(parsing_request->headers, sizeof(Request_header) * (index + 1));
    if (!new_headers)
    {
        YPRINTF("realloc failed\n");
    }
    parsing_request->headers = new_headers;
}
break;
case 19:
#line 247 "parser.y"
	{
    YPRINTF("parsing_request: Matched Success.\n");
    return SUCCESS;
}
break;
case 20:
#line 251 "parser.y"
	{
    YPRINTF("parsing_request: Matched Success.\n");
    return SUCCESS;
}
break;
#line 602 "y.tab.c"
    }
    yystack.s_mark -= yym;
    yystate = *yystack.s_mark;
    yystack.l_mark -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yystack.s_mark = YYFINAL;
        *++yystack.l_mark = yyval;
        if (yychar < 0)
        {
            if ((yychar = YYLEX) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yystack.s_mark, yystate);
#endif
    if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
    {
        goto yyoverflow;
    }
    *++yystack.s_mark = (short) yystate;
    *++yystack.l_mark = yyval;
    goto yyloop;

yyoverflow:
    yyerror("yacc stack overflow");

yyabort:
    yyfreestack(&yystack);
    return (1);

yyaccept:
    yyfreestack(&yystack);
    return (0);
}
