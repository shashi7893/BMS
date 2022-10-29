package com.bms.login.payload.response;

import lombok.Value;

import java.util.List;

@Value
public class UserInfoResponse {
    private Long id;
    private String username;
    private String email;
    private List<String> roles;
}
