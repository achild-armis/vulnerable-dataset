* CWE-89: SQL Injection
* Vulnerable: dynamic WHERE clause built from user input and passed
* directly into Open SQL, bypassing parameterization.
REPORT zcustomer_search.

PARAMETERS: p_cname TYPE kna1-name1.

DATA: lt_customers TYPE TABLE OF kna1,
      lv_where     TYPE string.

START-OF-SELECTION.

* VULNERABLE: user input concatenated directly into a dynamic WHERE
* clause string instead of using a bound placeholder / parameterized
* SELECT, allowing injection of arbitrary additional SQL conditions.
  CONCATENATE 'NAME1 = ''' p_cname '''' INTO lv_where.

  SELECT * FROM kna1
    INTO TABLE lt_customers
    WHERE (lv_where).

  LOOP AT lt_customers INTO DATA(ls_customer).
    WRITE: / ls_customer-kunnr, ls_customer-name1, ls_customer-ort01.
  ENDLOOP.

* VULNERABLE: a second dynamic-SQL entry point reachable from a
* different selection screen field, same unsanitized pattern.
  DATA(lv_city_filter) = |ORT01 = '{ p_cname }'|.
  SELECT * FROM kna1
    INTO TABLE lt_customers
    WHERE (lv_city_filter).
