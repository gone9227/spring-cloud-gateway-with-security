package com.scg.web.model.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@NoArgsConstructor
@AllArgsConstructor
@Data @Builder
public class LoginDto implements Serializable {
    private String userId;
    private String password;
}
