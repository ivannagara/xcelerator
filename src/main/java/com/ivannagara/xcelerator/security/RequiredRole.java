package com.ivannagara.xcelerator.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.ivannagara.xcelerator.model.Role;

// =================================================================
// 1) This RequiredRole can be applied to [Method] and [Classes, Interfaces, or Enums]
// e.g. =>
//
//  ________________________________________________________________
//  @RequiredRole(Role.ADMIN)                                       
//  public class AdminController {
//      ...
//  }
//  ________________________________________________________________
//  
//  { or }
//  ________________________________________________________________
//  public class UserController {
//      @RequiredRole(Role.MANAGER)
//      public void manageUsers() {
//         // This method requires a MANAGER role
//      }
//  }
//  ________________________________________________________________
//
// =================================================================
// 2) Retention Annotation reffers to how long the anotation is retained
//    in the program.
// e.g. =>
// [RetentionPolicy.RUNTIME] → The annotation is available at runtime, meaning it can be accessed through reflection.
// [RetentionPolicy.CLASS] → The annotation is stored in the ".class" file but not available at runtime.
// [RetentionPolicy.SOURCE] → The annotation is only present in the source code and gets removed during compilation.
// =================================================================
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiredRole {
    Role value() default Role.STAFF;
}
