package com.steellee.util.security;

public class ApiDto {

    private static final long serialVersionUID = 8772332967571243774L;

    private String inscode;
    private String tasknumbers;
    private String payername;
    private String payeridcard;
    private String totalamount;

    public String getInscode() {
        return inscode;
    }

    public void setInscode(String inscode) {
        this.inscode = inscode;
    }

    public String getTasknumbers() {
        return tasknumbers;
    }

    public void setTasknumbers(String tasknumbers) {
        this.tasknumbers = tasknumbers;
    }

    public String getPayername() {
        return payername;
    }

    public void setPayername(String payername) {
        this.payername = payername;
    }

    public String getPayeridcard() {
        return payeridcard;
    }

    public void setPayeridcard(String payeridcard) {
        this.payeridcard = payeridcard;
    }

    public String getTotalamount() {
        return totalamount;
    }

    public void setTotalamount(String totalamount) {
        this.totalamount = totalamount;
    }
}
