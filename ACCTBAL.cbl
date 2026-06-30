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

      *> VULNERABLE: no length check on WS-INPUT-NAME (up to 200 chars)
      *> before moving it into the 20-byte WS-CUSTOMER-NAME field; COBOL
      *> will silently truncate but adjacent unchecked paths in this
      *> codebase use unbounded REDEFINES that can corrupt memory.
           MOVE WS-INPUT-NAME TO WS-CUSTOMER-NAME.

           DISPLAY "ENTER TRANSACTION AMOUNT: "
           ACCEPT WS-INPUT-AMOUNT.

      *> VULNERABLE: no validation that WS-INPUT-AMOUNT is numeric or
      *> within an acceptable range before arithmetic, allowing corrupted
      *> or attacker-supplied data to produce incorrect balances.
           COMPUTE WS-BALANCE = WS-BALANCE + WS-INPUT-AMOUNT.

           DISPLAY "NEW BALANCE: " WS-BALANCE.
           STOP RUN.
