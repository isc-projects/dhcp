/* execute.c

   Support for executable statements. */

/*
 * Copyright (c) 1996-1999 Internet Software Consortium.
 * Use is subject to license terms which appear in the file named
 * ISC-LICENSE that should have accompanied this file when you
 * received it.   If a file named ISC-LICENSE did not accompany this
 * file, or you are not sure the one you have is correct, you may
 * obtain an applicable copy of the license at:
 *
 *             http://www.isc.org/isc-license-1.0.html. 
 *
 * This file is part of the ISC DHCP distribution.   The documentation
 * associated with this file is listed in the file DOCUMENTATION,
 * included in the top-level directory of this release.
 *
 * Support and other services are available for ISC products - see
 * http://www.isc.org for more information.
 */

#ifndef lint
static char copyright[] =
"$Id: execute.c,v 1.20 1999/10/01 03:16:46 mellon Exp $ Copyright (c) 1998, 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

int execute_statements (packet, lease, in_options, out_options, statements)
	struct packet *packet;
	struct lease *lease;
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
		      case statements_statement:
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: statements");
#endif
			status = execute_statements (packet, lease,
						     in_options, out_options,
						     r -> data.statements);
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: statements returns %d", status);
#endif
			if (!status)
				return 0;
			break;

		      case on_statement:
			if (lease) {
				struct executable_statement **d;
				switch (r -> data.on.evtype) {
				      case expiry:
					d = &lease -> on_expiry;
					break;
				      case commit:
					d = &lease -> on_commit;
					break;
				      case release:
					d = &lease -> on_release;
					break;
				      default:
					log_fatal ("unknown event type %d %s",
						   r -> data.on.evtype,
						   "in on statement.");
					break;
				}
				if (*d)
					executable_statement_dereference
						(d, "execute_statements");
				executable_statement_reference
					(d, r -> data.on.statements,
					 "execute_statements");
			}
			break;

		      case if_statement:
			status = evaluate_boolean_expression
				(&result, packet, lease,
				 in_options, out_options, r -> data.ie.expr);
			
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: if %s", (status
					      ? (result ? "true" : "false")
					      : "NULL"));
#endif
			/* XXX Treat NULL as false */
			if (!status)
				result = 0;
			if (!execute_statements
			    (packet, lease, in_options, out_options,
			     result ? r -> data.ie.true : r -> data.ie.false))
				return 0;
			break;

		      case eval_statement:
			status = evaluate_boolean_expression
				(&result, packet, lease,
				 in_options, out_options, r -> data.eval);
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: evaluate: %s",
			      (status
			       ? (result ? "true" : "false") : "NULL"));
#endif
			break;

		      case add_statement:
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: add %s", (r -> data.add -> name
					       ? r -> data.add -> name
					       : "<unnamed class>"));
#endif
			classify (packet, r -> data.add);
			break;

		      case break_statement:
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: break");
#endif
			return 0;

		      case supersede_option_statement:
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: supersede option %s.%s",
			      r -> data.option -> option -> universe -> name,
			      r -> data.option -> option -> name);
			goto option_statement;
#endif
		      case default_option_statement:
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: default option %s.%s",
			      r -> data.option -> option -> universe -> name,
			      r -> data.option -> option -> name);
			goto option_statement;
#endif
		      case append_option_statement:
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: append option %s.%s",
			      r -> data.option -> option -> universe -> name,
			      r -> data.option -> option -> name);
			goto option_statement;
#endif
		      case prepend_option_statement:
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: prepend option %s.%s",
			      r -> data.option -> option -> universe -> name,
			      r -> data.option -> option -> name);
		      option_statement:
#endif
			if (r -> data.option -> option -> universe -> set_func)
				((r -> data.option -> option ->
				  universe -> set_func)
				 (r -> data.option -> option -> universe,
				  out_options,
				  r -> data.option, r -> op));
			break;

		      default:
			log_fatal ("bogus statement type %d\n", r -> op);
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

void execute_statements_in_scope (packet, lease, in_options, out_options,
				  group, limiting_group)
	struct packet *packet;
	struct lease *lease;
	struct option_state *in_options;
	struct option_state *out_options;
	struct group *group;
	struct group *limiting_group;
{
	struct group *scope;
	struct group *limit;

	/* If we've recursed as far as we can, return. */
	if (!group)
		return;

	/* As soon as we get to a scope that is outer than the limiting
	   scope, we are done.   This is so that if somebody does something
	   like this, it does the expected thing:

	        domain-name "fugue.com";
		shared-network FOO {
			host bar {
				domain-name "othello.fugue.com";
				fixed-address 10.20.30.40;
			}
			subnet 10.20.30.0 netmask 255.255.255.0 {
				domain-name "manhattan.fugue.com";
			}
		}

	   The problem with the above arrangement is that the host's
	   group nesting will be host -> shared-network -> top-level,
	   and the limiting scope when we evaluate the host's scope
	   will be the subnet -> shared-network -> top-level, so we need
	   to know when we evaluate the host's scope to stop before we
	   evaluate the shared-networks scope, because it's outer than
	   the limiting scope, which means we've already evaluated it. */

	for (limit = limiting_group; limit; limit = limit -> next) {
		if (group == limit)
			return;
	}

	if (group -> next)
		execute_statements_in_scope (packet, lease,
					     in_options, out_options,
					     group -> next, limiting_group);
	execute_statements (packet, lease,
			    in_options, out_options, group -> statements);
}

/* Dereference or free any subexpressions of a statement being freed. */

int executable_statement_dereference (ptr, name)
	struct executable_statement **ptr;
	char *name;
{
	struct executable_statement *bp;

	if (!ptr || !*ptr) {
		log_error ("Null ptr in executable_statement_dereference: %s",
			   name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}

	(*ptr) -> refcnt--;
	if ((*ptr) -> refcnt) {
		*ptr = (struct executable_statement *)0;
		return 1;
	}

	if ((*ptr) -> next)
		executable_statement_dereference
			(&(*ptr) -> next, name);

	switch ((*ptr) -> op) {
	      case statements_statement:
		if ((*ptr) -> data.statements)
			executable_statement_dereference
				(&(*ptr) -> data.statements, name);
		break;

	      case on_statement:
		if ((*ptr) -> data.on.statements)
			executable_statement_dereference
				(&(*ptr) -> data.on.statements, name);
		break;

	      case if_statement:
		if ((*ptr) -> data.ie.expr)
			expression_dereference (&(*ptr) -> data.ie.expr, name);
		if ((*ptr) -> data.ie.true)
			executable_statement_dereference
				(&(*ptr) -> data.ie.true, name);
		if ((*ptr) -> data.ie.false)
			executable_statement_dereference
				(&(*ptr) -> data.ie.false, name);
		break;

	      case eval_statement:
		if ((*ptr) -> data.eval)
			expression_dereference (&(*ptr) -> data.eval, name);
		break;

	      case supersede_option_statement:
	      case default_option_statement:
	      case append_option_statement:
	      case prepend_option_statement:
		if ((*ptr) -> data.option)
			option_cache_dereference (&(*ptr) -> data.option,
						  name);
		break;

	      default:
		/* Nothing to do. */
		break;
	}

	dfree ((*ptr), name);
	*ptr = (struct executable_statement *)0;
	return 1;
}

void write_statements (file, statements, indent)
	FILE *file;
	struct executable_statement *statements;
	int indent;
{
	struct executable_statement *r, *x;
	int result;
	int status;
	char *s, *t, *dot;
	int col;

	if (!statements)
		return;

	for (r = statements; r; r = r -> next) {
		switch (r -> op) {
		      case statements_statement:
			write_statements (file, r -> data.statements, indent);
			break;

		      case on_statement:
			switch (r -> data.on.evtype) {
			      case expiry:
				s = "expiry";
				break;
			      case commit:
				s = "commit";
				break;
			      case release:
				s = "release";
				break;
			      default:
				log_fatal ("unknown event type %d %s",
					   r -> data.on.evtype,
					   "in on statement.");
			}
			indent_spaces (file, indent);
			fprintf (file, "on %s {", s);
			write_statements (file, r -> data.on.statements,
					  indent + 2);
			indent_spaces (file, indent);
			fprintf (file, "}");
			break;

		      case if_statement:
			indent_spaces (file, indent);
			fprintf (file, "if ");
			x = r;
			col = write_expression (file,
						x -> data.ie.expr,
						indent + 3, indent + 3);
		      else_if:
			token_print_indent (file, col, indent, " ", "", "{");
			write_statements (file, x -> data.ie.true, indent + 2);
			if (x -> data.ie.false &&
			    x -> data.ie.false -> op == if_statement &&
			    !x -> data.ie.false -> next) {
				indent_spaces (file, indent);
				fprintf (file, "} elsif ");
				x = x -> data.ie.false;
				col = write_expression (file,
							x -> data.ie.expr,
							indent + 6,
							indent + 6);
				goto else_if;
			}
			if (x -> data.ie.false) {
				indent_spaces (file, indent);
				fprintf (file, "} else {");
				write_statements (file, x -> data.ie.false,
						  indent + 2);
			}
			indent_spaces (file, indent);
			fprintf (file, "}");
			break;

		      case eval_statement:
			indent_spaces (file, indent);
			fprintf (file, "eval ");
			col = write_expression (file, r -> data.eval,
						indent + 5, indent + 5);
			fprintf (file, ";");
			break;

		      case add_statement:
			indent_spaces (file, indent);
			fprintf (file, "add \"%s\"", r -> data.add -> name);
			break;

		      case break_statement:
			indent_spaces (file, indent);
			fprintf (file, "break;");
			break;

		      case supersede_option_statement:
			s = "supersede";
			goto option_statement;

		      case default_option_statement:
			s = "default";
			goto option_statement;

		      case append_option_statement:
			s = "append";
			goto option_statement;

		      case prepend_option_statement:
			s = "prepend";
		      option_statement:
			/* Note: the reason we don't try to pretty print
			   the option here is that the format of the option
			   may change in dhcpd.conf, and then when this
			   statement was read back, it would cause a syntax
			   error. */
			if (r -> data.option -> option -> universe ==
			    &dhcp_universe) {
				t = "";
				dot = "";
			} else {
				t = (r -> data.option -> option ->
				     universe -> name);
				dot = ".";
			}
			indent_spaces (file, indent);
			fprintf (file, "%s %s%s%s = ", s, t, dot,
				 r -> data.option -> option -> name);
			col = (indent + strlen (s) + strlen (t) +
			       strlen (dot) + strlen (r -> data.option ->
						      option -> name) + 4);
			if (r -> data.option -> expression)
				write_expression
					(file,
					 r -> data.option -> expression,
					 col, indent + 8);
			else
				token_indent_data_string
					(file, col, indent + 8, "", "",
					 &r -> data.option -> data);
					 
			fprintf (file, ";"); /* XXX */
			break;

		      default:
			log_fatal ("bogus statement type %d\n", r -> op);
		}
	}
}
