* Fixed: CWE-89 SQL Injection.
* Both lookups now use static, parameterized Open SQL with a bound host
* variable instead of concatenating user input into a dynamic WHERE clause.
REPORT zcustomer_search.

PARAMETERS: p_cname TYPE kna1-name1.

DATA: lt_customers TYPE TABLE OF kna1.

START-OF-SELECTION.

  SELECT * FROM kna1
    INTO TABLE lt_customers
    WHERE name1 = p_cname.

  LOOP AT lt_customers INTO DATA(ls_customer).
    WRITE: / ls_customer-kunnr, ls_customer-name1, ls_customer-ort01.
  ENDLOOP.

  SELECT * FROM kna1
    INTO TABLE lt_customers
    WHERE ort01 = p_cname.
