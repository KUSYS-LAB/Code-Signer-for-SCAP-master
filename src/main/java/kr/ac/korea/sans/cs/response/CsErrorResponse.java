package kr.ac.korea.sans.cs.response;

public class CsErrorResponse extends RuntimeException {
    public CsErrorResponse(String msg) { super(msg); }
}
