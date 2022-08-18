package com.sugon.cloud.entity;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Random;
import java.util.UUID;

@Data
@NoArgsConstructor
public class AppUser implements Serializable {
   private static final long serialVersionUID = -1L;
   private UUID id = UUID.randomUUID();
   private String password = "password";
   private String firstName = "tiger";
   private String lastName = "xia";
   private String loginId = "10110";
}
