/* execute.c

   Support for executable statements. */

/*
 * Copyright (c) 1998 The Internet Software Consortium.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The Internet Software Consortium nor the names
 *    of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software has been written for the Internet Software Consortium
 * by Ted Lemon <mellon@fugue.com> in cooperation with Vixie
 * Enterprises.  To learn more about the Internet Software Consortium,
 * see ``http://www.vix.com/isc''.  To learn more about Vixie
 * Enterprises, see ``http://www.vix.com''.
 */

#ifndef lint
static char copyright[] =
"$Id: execute.c,v 1.4 1998/11/11 07:51:41 mellon Exp $ Copyright (c) 1998 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

int execute_statements (packet, in_options, out_options, statements)
	struct packet *packet;
	struct option_state *in_options;
	struct option_state *out_options;
	struct executable_statement *statements;
{
	struct executable_statement *r;
	int result;
	int status;

	if (!statements)
		return 1;

	for (r = statements; r; r = r -> next) {
		switch (r -> op) {
		      case if_statement:
			status = evaluate_boolean_expression
				(&result, packet,
				 in_options, r -> data.ie.expr);
			
#if defined (DEBUG_EXPRESSIONS)
			note ("exec: if %s", (status
					      ? (result ? "true" : "false")
					      : "NULL"));
#endif
			/* XXX Treat NULL as false */
			if (!status)
				result = 0;
			if (!execute_statements
			    (packet, in_options, out_options,
			     result ? r -> data.ie.true : r -> data.ie.false))
				return 0;
			break;

		      case eval_statement:
			status = evaluate_boolean_expression
				(&result,
				 packet, in_options, r -> data.eval);
#if defined (DEBUG_EXPRESSIONS)
			note ("exec: evaluate: %s",
			      (status
			       ? (result ? "true" : "false") : "NULL"));
#endif
			break;

		      case add_statement:
#if defined (DEBUG_EXPRESSIONS)
			note ("exec: add %s", (r -> data.add -> name
					       ? r -> data.add -> name
					       : "<unnamed class>"));
#endif
			classify (packet, r -> data.add);
			break;

		      case break_statement:
#if defined (DEBUG_EXPRESSIONS)
			note ("exec: break");
#endif
			return 0;

		      case supersede_option_statement:
#if defined (DEBUG_EXPRESSIONS)
			note ("exec: supersede option %s.%s",
			      r -> data.option -> option -> universe -> name,
			      r -> data.option -> option -> name);
			goto option_statement;
#endif
		      case default_option_statement:
#if defined (DEBUG_EXPRESSIONS)
			note ("exec: default option %s.%s",
			      r -> data.option -> option -> universe -> name,
			      r -> data.option -> option -> name);
			goto option_statement;
#endif
		      case append_option_statement:
#if defined (DEBUG_EXPRESSIONS)
			note ("exec: append option %s.%s",
			      r -> data.option -> option -> universe -> name,
			      r -> data.option -> option -> name);
			goto option_statement;
#endif
		      case prepend_option_statement:
#if defined (DEBUG_EXPRESSIONS)
			note ("exec: prepend option %s.%s",
			      r -> data.option -> option -> universe -> name,
			      r -> data.option -> option -> name);
		      option_statement:
#endif
			if (r -> data.option -> option -> universe -> set_func)
				(r -> data.option -> option ->
				 universe -> set_func) (out_options,
							r -> data.option,
							r -> op);
			break;

		      default:
			error ("bogus statement type %d\n", r -> op);
		}
	}

	return 1;
}

/* Execute all the statements in a particular scope, and all statements in
   scopes outer from that scope, but if a particular limiting scope is
   reached, do not execute statements in that scope or in scopes outer
   from it.   More specific scopes need to take precedence over less
   specific scopes, so we recursively traverse the scope list, executing
   the most outer scope first. */

void execute_statements_in_scope (packet, in_options, out_options,
				  group, limiting_group)
	struct packet *packet;
	struct option_state *in_options;
	struct option_state *out_options;
	struct group *group;
	struct group *limiting_group;
{
	struct group *scope;

	if (group == limiting_group)
		return;
	if (group -> next)
		execute_statements_in_scope (packet, in_options, out_options,
					     group -> next, limiting_group);
	execute_statements (packet,
			    in_options, out_options, group -> statements);
}
