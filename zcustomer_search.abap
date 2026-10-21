* CWE-89: SQL Injection
* Vulnerable: dynamic WHERE clause built from user input and passed
* directly into Open SQL, bypassing parameterization.
REPORT zcustomer_search.

PARAMETERS: p_cname TYPE kna1-name1.

DATA: lt_customers TYPE TABLE OF kna1.

START-OF-SELECTION.

* FIXED: user input is bound as an Open SQL host variable placeholder
* instead of being concatenated into a dynamic WHERE clause string,
* so it can never be interpreted as SQL syntax.
  SELECT * FROM kna1
    INTO TABLE lt_customers
    WHERE name1 = @p_cname.

  LOOP AT lt_customers INTO DATA(ls_customer).
    WRITE: / ls_customer-kunnr, ls_customer-name1, ls_customer-ort01.
  ENDLOOP.

* FIXED: same bound-placeholder pattern applied to the second
* dynamic-SQL entry point, replacing the template-literal interpolation.
  SELECT * FROM kna1
    INTO TABLE lt_customers
    WHERE ort01 = @p_cname.
