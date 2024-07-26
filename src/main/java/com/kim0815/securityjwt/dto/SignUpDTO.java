package com.kim0815.securityjwt.dto;

import com.kim0815.securityjwt.entity.Member;
import lombok.*;

@Setter
@Getter
@ToString
public class SignUpDTO {
    private Long id;
    private String username;
    private String password;
    @Builder
    public SignUpDTO(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public static Member toEntity(SignUpDTO signUpDTO) {
        return Member.builder()
                .username(signUpDTO.getUsername())
                .password(signUpDTO.getPassword())
                .build();
    }
}
