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
"$Id: execute.c,v 1.27 2000/02/02 08:01:45 mellon Exp $ Copyright (c) 1998, 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include <omapip/omapip_p.h>

int execute_statements (packet, lease, in_options, out_options, scope,
			statements)
	struct packet *packet;
	struct lease *lease;
	struct option_state *in_options;
	struct option_state *out_options;
	struct binding_scope *scope;
	struct executable_statement *statements;
{
	struct executable_statement *r, *e;
	int result;
	int status;
	unsigned long num;
	struct binding_scope *outer;
	struct binding *binding;
	struct data_string ds;
	struct binding_scope *ns;

	if (!statements)
		return 1;

	for (r = statements; r; r = r -> next) {
		switch (r -> op) {
		      case statements_statement:
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: statements");
#endif
			status = execute_statements (packet, lease, in_options,
						     out_options, scope,
						     r -> data.statements);
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: statements returns %d", status);
#endif
			if (!status)
				return 0;
			break;

		      case on_statement:
			if (lease) {
			    if (r -> data.on.evtypes & ON_EXPIRY) {
				if (lease -> on_expiry)
					executable_statement_dereference
						(&lease -> on_expiry, MDL);
				if (r -> data.on.statements)
					executable_statement_reference
						(&lease -> on_expiry,
						 r -> data.on.statements, MDL);
			    }
			    if (r -> data.on.evtypes & ON_RELEASE) {
				if (lease -> on_release)
					executable_statement_dereference
						(&lease -> on_release, MDL);
				if (r -> data.on.statements)
					executable_statement_reference
						(&lease -> on_release,
						 r -> data.on.statements, MDL);
			    }
			    if (r -> data.on.evtypes & ON_COMMIT) {
				if (lease -> on_commit)
					executable_statement_dereference
						(&lease -> on_commit, MDL);
				if (r -> data.on.statements)
					executable_statement_reference
						(&lease -> on_commit,
						 r -> data.on.statements, MDL);
			    }
			}
			break;

		      case switch_statement:
			e = find_matching_case (packet, lease,
						in_options, out_options, scope,
						r -> data.s_switch.expr,
						r -> data.s_switch.statements);
			if (e && !execute_statements (packet, lease,
						      in_options, out_options,
						      scope, e))
				return 0;

			/* These have no effect when executed. */
		      case case_statement:
		      case default_statement:
			break;

		      case if_statement:
			status = evaluate_boolean_expression
				(&result, packet, lease, in_options,
				 out_options, scope, r -> data.ie.expr);
			
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: if %s", (status
					      ? (result ? "true" : "false")
					      : "NULL"));
#endif
			/* XXX Treat NULL as false */
			if (!status)
				result = 0;
			if (!execute_statements
			    (packet, lease, in_options, out_options, scope,
			     result ? r -> data.ie.true : r -> data.ie.false))
				return 0;
			break;

		      case eval_statement:
			if (is_boolean_expression (r -> data.eval)) {
				status = (evaluate_boolean_expression
					  (&result, packet, lease, in_options,
					   out_options, scope,
					   r -> data.eval));
			} else if (is_numeric_expression (r -> data.eval)) {
				status = (evaluate_numeric_expression
					  (&num, packet, lease, in_options,
					   out_options, scope,
					   r -> data.eval));
			} else if (is_data_expression  (r -> data.eval)) {
				memset (&ds, 0, sizeof ds);
				status = (evaluate_data_expression
					  (&ds, packet, lease, in_options,
					   out_options, scope,
					   r -> data.eval));
				if (status && ds.data)
					data_string_forget (&ds, MDL);
			} else if (is_dns_expression (r -> data.eval)) {
#if defined (NSUPDATE)
				ns_updrec *nut;
				nut = 0;
				status = (evaluate_dns_expression
					  (&nut, packet, lease, in_options,
					   out_options, scope,
					   r -> data.eval));
				if (status) {
					if (nut -> r_data) {
						dfree (nut -> r_data, MDL);
						nut -> r_data = (char *)0;
					}
					if (nut -> r_dname) {
						dfree (nut -> r_dname, MDL);
						nut -> r_dname = (char *)0;
					}
					minires_freeupdrec (nut);
				}
#endif
			} else {
				log_error ("%s: invalid expression type: %d",
					   "execute_statements",
					   r -> data.eval -> op);
			}

#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: evaluate: %s",
				   (status "succeeded" : "failed"));
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

		      case set_statement:
			memset (&ds, 0, sizeof ds);
			status = (evaluate_data_expression
				  (&ds, packet, lease, in_options, out_options,
				   scope, r -> data.set.expr));

			binding = find_binding (scope, r -> data.set.name);
			if (!binding && status) {
				binding = dmalloc (sizeof *binding, MDL);
				if (binding) {
				    binding -> name =
					    dmalloc (strlen
						     (r -> data.set.name) + 1,
						     MDL);
				    if (binding -> name) {
					strcpy (binding -> name,
						r -> data.set.name);
					if (lease) {
					    binding -> next =
						    lease -> scope.bindings;
					    lease -> scope.bindings = binding;
					} else {
					    binding -> next =
						    global_scope.bindings;
					    global_scope.bindings = binding;
					}
				    } else {
				       badalloc:
					dfree (binding, MDL);
					binding = (struct binding *)0;
				    }
				}
			}
			if (binding) {
				if (binding -> value.data)
				    data_string_forget (&binding -> value,
							MDL);
				if (status)
				    data_string_copy (&binding -> value, &ds,
						      MDL);
			}
			if (status)
			    data_string_forget (&ds, MDL);
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: set %s = %s", r -> data.set.name,
				   (status && binding
				    ? print_hex_1 (binding -> value.len,
						   binding -> value.data, 50)
				    : "NULL"));
#endif
			break;

		      case unset_statement:
			binding = find_binding (scope, r -> data.unset);
			if (binding) {
				if (binding -> value.data)
					data_string_forget (&binding -> value,
							    MDL);
				status = 1;
			} else
				status = 0;
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: unset %s: %s", r -> data.unset,
				   (status ? "found" : "NULL"));
#endif
			break;

		      case let_statement:
			memset (&ds, 0, sizeof ds);
			status = (evaluate_data_expression
				  (&ds, packet, lease, in_options, out_options,
				   scope, r -> data.let.expr));

			ns = (struct binding_scope *)0;
			binding_scope_allocate (&ns, MDL);

		      next_let:
			if (ns) {
				binding = dmalloc (sizeof *binding, MDL);
				if (!binding) {
				   blb:
				    binding_scope_dereference (&ns, MDL);
				} else {
				    binding -> name =
					    dmalloc (strlen
						     (r -> data.let.name + 1),
						     MDL);
				    if (binding -> name)
					strcpy (binding -> name,
						r -> data.let.name);
				    else {
					dfree (binding, MDL);
					binding = (struct binding *)0;
					goto blb;
				    }
				}
			}
			if (ns && binding && status) {
				data_string_copy (&binding -> value, &ds, MDL);
				binding -> next = ns -> bindings;
				ns -> bindings = binding;
			}

			if (status)
			    data_string_forget (&ds, MDL);
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("exec: let %s = %s", r -> data.let.name,
				   (status && binding
				    ? print_hex_1 (binding -> value.len,
						   binding -> value.data, 50)
				    : "NULL"));
#endif
			if (!r -> data.let.statements) {
			} else if (r -> data.let.statements -> op ==
				   let_statement) {
				r = r -> data.let.statements;
				goto next_let;
			} else if (ns) {
				ns -> outer = scope;
				execute_statements
				      (packet, lease, in_options, out_options,
				       ns, r -> data.let.statements);
			}
			if (ns)
				binding_scope_dereference (&ns, MDL);
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
				  scope, group, limiting_group)
	struct packet *packet;
	struct lease *lease;
	struct option_state *in_options;
	struct option_state *out_options;
	struct binding_scope *scope;
	struct group *group;
	struct group *limiting_group;
{
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
					     in_options, out_options, scope,
					     group -> next, limiting_group);
	execute_statements (packet, lease, in_options, out_options, scope,
			    group -> statements);
}

/* Dereference or free any subexpressions of a statement being freed. */

int executable_statement_dereference (ptr, file, line)
	struct executable_statement **ptr;
	const char *file;
	int line;
{
	struct executable_statement *bp;

	if (!ptr || !*ptr) {
		log_error ("%s(%d): null pointer", file, line);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}

	(*ptr) -> refcnt--;
	rc_register (file, line, ptr, *ptr, (*ptr) -> refcnt);
	if ((*ptr) -> refcnt > 0) {
		*ptr = (struct executable_statement *)0;
		return 1;
	}

	if ((*ptr) -> refcnt < 0) {
		log_error ("%s(%d): negative refcnt!", file, line);
#if defined (DEBUG_RC_HISTORY)
		dump_rc_history ();
#endif
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}

	if ((*ptr) -> next)
		executable_statement_dereference (&(*ptr) -> next, file, line);

	switch ((*ptr) -> op) {
	      case statements_statement:
		if ((*ptr) -> data.statements)
			executable_statement_dereference
				(&(*ptr) -> data.statements, file, line);
		break;

	      case on_statement:
		if ((*ptr) -> data.on.statements)
			executable_statement_dereference
				(&(*ptr) -> data.on.statements, file, line);
		break;

	      case switch_statement:
		if ((*ptr) -> data.s_switch.statements)
			executable_statement_dereference
				(&(*ptr) -> data.on.statements, file, line);
		if ((*ptr) -> data.s_switch.expr)
			expression_dereference (&(*ptr) -> data.s_switch.expr,
						file, line);
		break;

	      case case_statement:
		if ((*ptr) -> data.s_switch.expr)
			expression_dereference (&(*ptr) -> data.c_case,
						file, line);
		break;

	      case if_statement:
		if ((*ptr) -> data.ie.expr)
			expression_dereference (&(*ptr) -> data.ie.expr,
						file, line);
		if ((*ptr) -> data.ie.true)
			executable_statement_dereference
				(&(*ptr) -> data.ie.true, file, line);
		if ((*ptr) -> data.ie.false)
			executable_statement_dereference
				(&(*ptr) -> data.ie.false, file, line);
		break;

	      case eval_statement:
		if ((*ptr) -> data.eval)
			expression_dereference (&(*ptr) -> data.eval,
						file, line);
		break;

	      case set_statement:
		if ((*ptr)->data.set.name)
			dfree ((*ptr)->data.set.name, file, line);
		if ((*ptr)->data.set.expr)
			expression_dereference (&(*ptr) -> data.set.expr,
						file, line);
		break;

	      case unset_statement:
		if ((*ptr)->data.unset)
			dfree ((*ptr)->data.unset, file, line);
		break;

	      case supersede_option_statement:
	      case default_option_statement:
	      case append_option_statement:
	      case prepend_option_statement:
		if ((*ptr) -> data.option)
			option_cache_dereference (&(*ptr) -> data.option,
						  file, line);
		break;

	      default:
		/* Nothing to do. */
		break;
	}

	dfree ((*ptr), file, line);
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
	const char *s, *t, *dot;
	int col;

	if (!statements)
		return;

	for (r = statements; r; r = r -> next) {
		switch (r -> op) {
		      case statements_statement:
			write_statements (file, r -> data.statements, indent);
			break;

		      case on_statement:
			indent_spaces (file, indent);
			fprintf (file, "on ");
			s = "";
			if (r -> data.on.evtypes & ON_EXPIRY) {
				fprintf (file, "%sexpiry", s);
				s = " or ";
			}
			if (r -> data.on.evtypes & ON_COMMIT) {
				fprintf (file, "%scommit", s);
				s = "or";
			}
			if (r -> data.on.evtypes & ON_RELEASE) {
				fprintf (file, "%srelease", s);
				s = "or";
			}
			if (r -> data.on.statements) {
				fprintf (file, " {");
				write_statements (file,
						  r -> data.on.statements,
						  indent + 2);
				indent_spaces (file, indent);
				fprintf (file, "}");
			} else {
				fprintf (file, ";");
			}
			break;

		      case switch_statement:
			indent_spaces (file, indent);
			fprintf (file, "switch (");
			col = write_expression (file,
						r -> data.s_switch.expr,
						indent + 7, indent + 7, 1);
			col = token_print_indent (file, col, indent + 7,
						  "", "", ")");
			token_print_indent (file,
					    col, indent, " ", "", "{");
			write_statements (file, r -> data.s_switch.statements,
					  indent + 2);
			indent_spaces (file, indent);
			fprintf (file, "}");
			break;
			
		      case case_statement:
			indent_spaces (file, indent - 1);
			fprintf (file, "case ");
			col = write_expression (file,
						r -> data.s_switch.expr,
						indent + 5, indent + 5, 1);
			token_print_indent (file, col, indent + 5,
					    "", "", ":");
			break;
			
		      case default_statement:
			indent_spaces (file, indent - 1);
			fprintf (file, "default: ");
			break;

		      case if_statement:
			indent_spaces (file, indent);
			fprintf (file, "if ");
			x = r;
			col = write_expression (file,
						x -> data.ie.expr,
						indent + 3, indent + 3, 1);
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
							indent + 6, 1);
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
						indent + 5, indent + 5, 1);
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
					 col, indent + 8, 1);
			else
				token_indent_data_string
					(file, col, indent + 8, "", "",
					 &r -> data.option -> data);
					 
			fprintf (file, ";"); /* XXX */
			break;

		      case set_statement:
			indent_spaces (file, indent);
			fprintf (file, "set ");
			col = token_print_indent (file, indent + 4, indent + 4,
						  "", "", r -> data.set.name);
			col = token_print_indent (file, col, indent + 4,
						  " ", " ", "=");
			col = write_expression (file, r -> data.set.expr,
						indent + 3, indent + 3, 0);
			col = token_print_indent (file, col, indent + 4,
						  " ", "", ";");
			break;
			
		      case unset_statement:
			indent_spaces (file, indent);
			fprintf (file, "unset ");
			col = token_print_indent (file, indent + 6, indent + 6,
						  "", "", r -> data.set.name);
			col = token_print_indent (file, col, indent + 6,
						  " ", "", ";");
			break;
			
		      default:
			log_fatal ("bogus statement type %d\n", r -> op);
		}
	}
}

/* Find a case statement in the sequence of executable statements that
   matches the expression, and if found, return the following statement.
   If no case statement matches, try to find a default statement and
   return that (the default statement can precede all the case statements).
   Otherwise, return the null statement. */

struct executable_statement *find_matching_case (packet, lease, in_options,
						 out_options, scope,
						 expr, stmt)
	struct packet *packet;
	struct lease *lease;
	struct option_state *in_options;
	struct option_state *out_options;
	struct binding_scope *scope;
	struct expression *expr;
	struct executable_statement *stmt;
{
	int status, sub;
	struct executable_statement *s;
	unsigned long foo;

	if (is_data_expression (expr)) {
		struct executable_statement *e;
		struct data_string cd, ds;
		memset (&ds, 0, sizeof ds);
		memset (&cd, 0, sizeof cd);

		status = (evaluate_data_expression (&ds, packet, lease,
						    in_options, out_options,
						    scope, expr));
		if (status) {
		    for (s = stmt; s; s = s -> next) {
			if (s -> op == case_statement) {
				sub = (evaluate_data_expression
				       (&cd, packet, lease, in_options,
					out_options, scope, s -> data.c_case));
				if (sub && cd.len == ds.len &&
				    !memcmp (cd.data, ds.data, cd.len))
				{
					data_string_forget (&cd, MDL);
					data_string_forget (&ds, MDL);
					return s -> next;
				}
				data_string_forget (&cd, MDL);
			}
		    }
		    data_string_forget (&ds, MDL);
		}
	} else {
		unsigned long n, c;
		status = evaluate_numeric_expression (&n, packet, lease,
						      in_options, out_options,
						      scope, expr);

		if (status) {
		    for (s = stmt; s; s = s -> next) {
			if (s -> op == case_statement) {
				sub = (evaluate_numeric_expression
				       (&c, packet, lease, in_options,
					out_options, scope, s -> data.c_case));
				if (sub && n == c)
					return s -> next;
			}
		    }
		}
	}

	/* If we didn't find a matching case statement, look for a default
	   statement and return the statement following it. */
	for (s = stmt; s; s = s -> next)
		if (s -> op == default_statement)
			break;
	if (s)
		return s -> next;
	return (struct executable_statement *)0;
}
