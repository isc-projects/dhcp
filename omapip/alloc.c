/* alloc.c

   Functions supporting memory allocation for the object management
   protocol... */

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

#include <omapip/omapip_p.h>

isc_result_t omapi_object_reference (omapi_object_t **r,
				     omapi_object_t *h,
				     const char *file, int line)
{
	if (!h || !r)
		return ISC_R_INVALIDARG;

	if (*r) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("%s(%d): reference store into non-null pointer!",
		       file, line);
#else
		return ISC_R_INVALIDARG;
#endif
	}
	*r = h;
	h -> refcnt++;
	rc_register (file, line, h, h -> refcnt);
	dmalloc_reuse (h, file, line, 1);
	return ISC_R_SUCCESS;
}

isc_result_t omapi_object_dereference (omapi_object_t **h,
				       const char *name)
{
	int outer_reference = 0;
	int inner_reference = 0;
	int handle_reference = 0;
	int extra_references;
	omapi_object_t *p;

	if (!h)
		return ISC_R_INVALIDARG;

	if (!*h) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("%s: dereference of null pointer!", name);
#else
		return ISC_R_INVALIDARG;
#endif
	}
	
	if ((*h) -> refcnt <= 0) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("dereference of pointer with refcnt of zero!");
#else
		return ISC_R_INVALIDARG;
#endif
	}
	
	/* See if this object's inner object refers to it, but don't
	   count this as a reference if we're being asked to free the
	   reference from the inner object. */
	if ((*h) -> inner && (*h) -> inner -> outer &&
	    h != &((*h) -> inner -> outer))
		inner_reference = 1;

	/* Ditto for the outer object. */
	if ((*h) -> outer && (*h) -> outer -> inner &&
	    h != &((*h) -> outer -> inner))
		outer_reference = 1;

	/* Ditto for the outer object.  The code below assumes that
	   the only reason we'd get a dereference from the handle
	   table is if this function does it - otherwise we'd have to
	   traverse the handle table to find the address where the
	   reference is stored and compare against that, and we don't
	   want to do that if we can avoid it. */
	if ((*h) -> handle)
		handle_reference = 1;

	/* If we are getting rid of the last reference other than
	   references to inner and outer objects, or from the handle
	   table, then we must examine all the objects in either
	   direction to see if they hold any non-inner, non-outer,
	   non-handle-table references.  If not, we need to free the
	   entire chain of objects. */
	if ((*h) -> refcnt ==
	    inner_reference + outer_reference + handle_reference + 1) {
		if (inner_reference || outer_reference || handle_reference) {
			/* XXX we could check for a reference from the
                           handle table here. */
			extra_references = 0;
			for (p = (*h) -> inner;
			     p && !extra_references; p = p -> inner) {
				extra_references += p -> refcnt - 1;
				if (p -> inner)
					--extra_references;
				if (p -> handle)
					--extra_references;
			}
			for (p = (*h) -> outer;
			     p && !extra_references; p = p -> outer) {
				extra_references += p -> refcnt - 1;
				if (p -> outer)
					--extra_references;
				if (p -> handle)
					--extra_references;
			}
		} else
			extra_references = 0;

		if (!extra_references) {
			if (inner_reference)
				omapi_object_dereference
					(&(*h) -> inner -> outer, file, line);
			if (outer_reference)
				omapi_object_dereference
					(&(*h) -> outer -> inner, file, line);
			rc_register (file, line, *h, 0);
			if ((*h) -> type -> destroy)
				(*((*h) -> type -> destroy)) (*h, file, line);
			dfree (*h, file, line);
		}
	} else {
		(*h) -> refcnt--;
		rc_register (file, line, *h, (*h) -> refcnt);
	}
	*h = 0;
	return ISC_R_SUCCESS;
}

isc_result_t omapi_buffer_new (omapi_buffer_t **h,
			       const char *file, int line)
{
	omapi_buffer_t *t;
	isc_result_t status;
	
	t = (omapi_buffer_t *)dmalloc (sizeof *t, file, line);
	if (!t)
		return ISC_R_NOMEMORY;
	memset (t, 0, sizeof *t);
	status = omapi_buffer_reference (h, t, file, line);
	if (status != ISC_R_SUCCESS)
		dfree (t, file, line);
	(*h) -> head = sizeof ((*h) -> buf) - 1;
	return status;
}

isc_result_t omapi_buffer_reference (omapi_buffer_t **r,
				     omapi_buffer_t *h,
				     const char *file, int line)
{
	if (!h || !r)
		return ISC_R_INVALIDARG;

	if (*r) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("%s: reference store into non-null pointer!", name);
#else
		return ISC_R_INVALIDARG;
#endif
	}
	*r = h;
	h -> refcnt++;
	rc_register (file, line, h, h -> refcnt);
	dmalloc_reuse (h, file, line, 1);
	return ISC_R_SUCCESS;
}

isc_result_t omapi_buffer_dereference (omapi_buffer_t **h,
				       const char *name)
{
	if (!h)
		return ISC_R_INVALIDARG;

	if (!*h) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("%s(%d): dereference of null pointer!", file, line);
#else
		return ISC_R_INVALIDARG;
#endif
	}
	
	if ((*h) -> refcnt <= 0) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("%s(%d): dereference of pointer with refcnt of zero!", 
		       file, line);
#else
		return ISC_R_INVALIDARG;
#endif
	}
	--(*h) -> refcnt;
	rc_register (file, line, h, (*h) -> refcnt);
	if ((*h) -> refcnt == 0)
		dfree (*h, file, line);
	*h = 0;
	return ISC_R_SUCCESS;
}

isc_result_t omapi_typed_data_new (omapi_typed_data_t **t,
				   omapi_datatype_t type, ...)
{
	va_list l;
	omapi_typed_data_t *new;
	unsigned len;
	unsigned val;
	int intval;
	char *s;
	isc_result_t status;
	const char *file;
	int line;
	omapi_object_t *obj;

	va_start (l, type);

	switch (type) {
	      case omapi_datatype_int:
		len = OMAPI_TYPED_DATA_INT_LEN;
		intval = va_arg (l, int);
		break;
	      case omapi_datatype_string:
		s = va_arg (l, char *);
		val = strlen (s);
		len = OMAPI_TYPED_DATA_NOBUFFER_LEN + val;
		break;
	      case omapi_datatype_data:
		val = va_arg (l, unsigned);
		len = OMAPI_TYPED_DATA_NOBUFFER_LEN + val;
		break;
	      case omapi_datatype_object:
		len = OMAPI_TYPED_DATA_OBJECT_LEN;
		obj = va_arg (l, omapi_object_t *);
		break;
	      default:
		return ISC_R_INVALIDARG;
	}

	/* XXX not necessary if not doing malloc debugging. */
	file = va_arg (l, const char *);
	line = va_arg (l, int);

	new = dmalloc (len, file, line);
	if (!new)
		return ISC_R_NOMEMORY;
	memset (new, 0, len);

	switch (type) {
	      case omapi_datatype_int:
		new -> u.integer = intval;
		break;
	      case omapi_datatype_string:
		memcpy (new -> u.buffer.value, s, val);
		new -> u.buffer.len = val;
		break;
	      case omapi_datatype_data:
		new -> u.buffer.len = val;
		break;
	      case omapi_datatype_object:
		status = omapi_object_reference (&new -> u.object, obj,
						 file, line);
		if (status != ISC_R_SUCCESS) {
			dfree (new, file, line);
			return status;
		}
		break;
	}
	new -> type = type;

	return omapi_typed_data_reference (t, new, file, line);
}

isc_result_t omapi_typed_data_reference (omapi_typed_data_t **r,
					 omapi_typed_data_t *h,
					 const char *file, int line)
{
	if (!h || !r)
		return ISC_R_INVALIDARG;

	if (*r) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("%s: reference store into non-null pointer!", name);
#else
		return ISC_R_INVALIDARG;
#endif
	}
	*r = h;
	h -> refcnt++;
	rc_register (file, line, h, h -> refcnt);
	dmalloc_reuse (h, file, line, 1);
	return ISC_R_SUCCESS;
}

isc_result_t omapi_typed_data_dereference (omapi_typed_data_t **h,
					   const char *file, line)
{
	if (!h)
		return ISC_R_INVALIDARG;

	if (!*h) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("%s: dereference of null pointer!", name);
#else
		return ISC_R_INVALIDARG;
#endif
	}
	
	if ((*h) -> refcnt <= 0) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("dereference of pointer with refcnt of zero!");
#else
		return ISC_R_INVALIDARG;
#endif
	}
	
	--((*h) -> refcnt);
	rc_register (file, line, *h, (*h) -> refcnt);
	if ((*h) -> refcnt <= 0 ) {
		switch ((*h) -> type) {
		      case omapi_datatype_int:
		      case omapi_datatype_string:
		      case omapi_datatype_data:
		      default:
			break;
		      case omapi_datatype_object:
			omapi_object_dereference (&(*h) -> u.object,
						  file, line);
			break;
		}
		dfree (*h, file, line);
	}
	*h = 0;
	return ISC_R_SUCCESS;
}

isc_result_t omapi_data_string_new (omapi_data_string_t **d, unsigned len,
				    const char *file, int line)
{
	omapi_data_string_t *new;

	new = dmalloc (OMAPI_DATA_STRING_EMPTY_SIZE + len, file, line);
	if (!new)
		return ISC_R_NOMEMORY;
	memset (new, 0, OMAPI_DATA_STRING_EMPTY_SIZE);
	new -> len = len;
	return omapi_data_string_reference (d, new, file, line);
}

isc_result_t omapi_data_string_reference (omapi_data_string_t **r,
					  omapi_data_string_t *h,
					  const char *file, line)
{
	if (!h || !r)
		return ISC_R_INVALIDARG;

	if (*r) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("%s: reference store into non-null pointer!", name);
#else
		return ISC_R_INVALIDARG;
#endif
	}
	*r = h;
	h -> refcnt++;
	rc_register (file, line, h, h -> refcnt);
	dmalloc_reuse (h, file, line, 1);
	return ISC_R_SUCCESS;
}

isc_result_t omapi_data_string_dereference (omapi_data_string_t **h,
					    const char *file, line)
{
	if (!h)
		return ISC_R_INVALIDARG;

	if (!*h) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("%s(%d): dereference of null pointer!", file, line);
#else
		return ISC_R_INVALIDARG;
#endif
	}
	
	if ((*h) -> refcnt <= 0) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("%s(%d): dereference of pointer with refcnt of zero!",
		       file, line);
#else
		return ISC_R_INVALIDARG;
#endif
	}
	
	--((*h) -> refcnt);
	rc_register (file, line, h, h -> refcnt);
	if ((*h) -> refcnt <= 0 ) {
		dfree (*h, file, line);
	}
	*h = 0;
	return ISC_R_SUCCESS;
}

isc_result_t omapi_value_new (omapi_value_t **d,
			      const char *file, int line)
{
	omapi_value_t *new;

	new = dmalloc (sizeof *new, file, line);
	if (!new)
		return ISC_R_NOMEMORY;
	memset (new, 0, sizeof *new);
	return omapi_value_reference (d, new, file, line);
}

isc_result_t omapi_value_reference (omapi_value_t **r,
				    omapi_value_t *h,
				    const char *file, line)
{
	if (!h || !r)
		return ISC_R_INVALIDARG;

	if (*r) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("%s(%d): reference store into non-null pointer!",
		       file, line);
#else
		return ISC_R_INVALIDARG;
#endif
	}
	*r = h;
	h -> refcnt++;
	rc_register (file, line, h, h -> refcnt);
	dmalloc_reuse (h, file, line, 1);
	return ISC_R_SUCCESS;
}

isc_result_t omapi_value_dereference (omapi_value_t **h,
				      const char *name)
{
	if (!h)
		return ISC_R_INVALIDARG;

	if (!*h) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("%s(%d): dereference of null pointer!", file, line);
#else
		return ISC_R_INVALIDARG;
#endif
	}
	
	if ((*h) -> refcnt <= 0) {
#if defined (ALLOCATION_DEBUGGING)
		abort ("%s(%d): dereference of pointer with refcnt of zero!",
		       file, line);
#else
		return ISC_R_INVALIDARG;
#endif
	}
	
	--((*h) -> refcnt);
	rc_register (file, line, h, h -> refcnt);
	if ((*h) -> refcnt <= 0 ) {
		if ((*h) -> name)
			omapi_data_string_dereference (&(*h) -> name, name);
		if ((*h) -> value)
			omapi_typed_data_dereference (&(*h) -> value, name);
		dfree (*h, file, line);
	}
	*h = 0;
	return ISC_R_SUCCESS;
}

