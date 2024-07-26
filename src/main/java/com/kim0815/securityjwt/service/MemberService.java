package com.kim0815.securityjwt.service;

import com.kim0815.securityjwt.dto.JwtToken;

public interface MemberService {
    JwtToken signIn(String username, String password);
}
