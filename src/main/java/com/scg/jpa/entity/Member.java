package com.scg.jpa.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;

@Data @NoArgsConstructor @AllArgsConstructor
@Entity
public class Member {
    @Id
    private String userId;
    @Column(nullable = false)
    private String password;
    private String role;
}
