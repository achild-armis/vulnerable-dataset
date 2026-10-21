      *> CWE-20: Improper Input Validation
      *> CWE-787: Out-of-bounds Write
      *> Vulnerable: fixed-length field receives unchecked external input,
      *> and numeric fields are used in arithmetic without range validation,
      *> a common source of overflow and data corruption in COBOL batch jobs.
       IDENTIFICATION DIVISION.
       PROGRAM-ID. ACCTBAL.

       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01  WS-ACCOUNT-RECORD.
           05  WS-ACCOUNT-ID       PIC X(10).
      *> VULNERABLE: fixed 20-byte field, no length check before MOVE
           05  WS-CUSTOMER-NAME    PIC X(20).
           05  WS-BALANCE          PIC 9(7)V99.
           05  WS-TRANSACTION-AMT  PIC 9(7)V99.

       01  WS-INPUT-NAME           PIC X(200).
       01  WS-INPUT-AMOUNT         PIC X(50).

       PROCEDURE DIVISION.
       MAIN-LOGIC.
           DISPLAY "ENTER CUSTOMER NAME: "
           ACCEPT WS-INPUT-NAME.

      *> FIX (CWE-787): validate length before moving into the fixed
      *> 20-byte field; reject (do not move) input that would overflow it.
           IF FUNCTION LENGTH(FUNCTION TRIM(WS-INPUT-NAME)) > 20
               DISPLAY "ERROR: CUSTOMER NAME EXCEEDS 20 CHARACTERS"
               MOVE SPACES TO WS-CUSTOMER-NAME
           ELSE
               MOVE WS-INPUT-NAME TO WS-CUSTOMER-NAME
           END-IF.

           DISPLAY "ENTER TRANSACTION AMOUNT: "
           ACCEPT WS-INPUT-AMOUNT.

      *> FIX (CWE-20): validate WS-INPUT-AMOUNT is numeric and within an
      *> acceptable range before using it in arithmetic; reject otherwise.
           IF WS-INPUT-AMOUNT IS NUMERIC
               AND WS-INPUT-AMOUNT >= 0
               AND WS-INPUT-AMOUNT <= 9999999.99
               COMPUTE WS-BALANCE = WS-BALANCE + WS-INPUT-AMOUNT
           ELSE
               DISPLAY "ERROR: INVALID TRANSACTION AMOUNT"
           END-IF.

           DISPLAY "NEW BALANCE: " WS-BALANCE.
           STOP RUN.
