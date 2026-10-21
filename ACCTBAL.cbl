      *> Fixed: CWE-20 Improper Input Validation and CWE-787
      *> Out-of-bounds Write. The customer name is now length-checked
      *> before MOVE, and the transaction amount is validated as numeric
      *> and range-checked before being used in arithmetic.
       IDENTIFICATION DIVISION.
       PROGRAM-ID. ACCTBAL.

       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01  WS-ACCOUNT-RECORD.
           05  WS-ACCOUNT-ID       PIC X(10).
           05  WS-CUSTOMER-NAME    PIC X(20).
           05  WS-BALANCE          PIC 9(7)V99.
           05  WS-TRANSACTION-AMT  PIC 9(7)V99.

       01  WS-INPUT-NAME           PIC X(200).
       01  WS-INPUT-AMOUNT         PIC X(50).
       01  WS-NAME-LENGTH          PIC 9(3).

       PROCEDURE DIVISION.
       MAIN-LOGIC.
           DISPLAY "ENTER CUSTOMER NAME: "
           ACCEPT WS-INPUT-NAME.

           INSPECT FUNCTION REVERSE(WS-INPUT-NAME)
               TALLYING WS-NAME-LENGTH FOR LEADING SPACES.
           COMPUTE WS-NAME-LENGTH = LENGTH OF WS-INPUT-NAME - WS-NAME-LENGTH.

           IF WS-NAME-LENGTH > LENGTH OF WS-CUSTOMER-NAME
               DISPLAY "ERROR: CUSTOMER NAME TOO LONG"
               STOP RUN
           END-IF.

           MOVE WS-INPUT-NAME TO WS-CUSTOMER-NAME.

           DISPLAY "ENTER TRANSACTION AMOUNT: "
           ACCEPT WS-INPUT-AMOUNT.

           IF WS-INPUT-AMOUNT IS NOT NUMERIC
               DISPLAY "ERROR: TRANSACTION AMOUNT MUST BE NUMERIC"
               STOP RUN
           END-IF.

           MOVE WS-INPUT-AMOUNT TO WS-TRANSACTION-AMT.

           IF WS-TRANSACTION-AMT < 0 OR WS-TRANSACTION-AMT > 9999999.99
               DISPLAY "ERROR: TRANSACTION AMOUNT OUT OF RANGE"
               STOP RUN
           END-IF.

           COMPUTE WS-BALANCE = WS-BALANCE + WS-TRANSACTION-AMT.

           DISPLAY "NEW BALANCE: " WS-BALANCE.
           STOP RUN.
