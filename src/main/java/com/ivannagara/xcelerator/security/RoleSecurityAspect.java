package com.ivannagara.xcelerator.security;

import java.lang.reflect.Method;
import java.util.Map;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import com.ivannagara.xcelerator.model.Role;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Aspect
@Component
@Slf4j
public class RoleSecurityAspect {
    /**
     * 
     * @param joinPoint
     * @return
     * @throws Throwable
     * 
     * This function will be called everytime a function is anotated with the @RequiredRole(...Role...);
     * It will be called because (1) it has the @Around annotation and (2) the input param of [ProceedingJoinPoint].
     */
    @Around("@annotation(com.ivannagara.xcelerator.security.RequiredRole) || @within(com.ivannagara.xcelerator.security.RequiredRole)")
    public Object checkRole(ProceedingJoinPoint joinPoint) throws Throwable {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();

        // Get user role from request attributes (set by FirebaseAuthFilter)
        Role userRole = (Role) request.getAttribute("userRole");

        if (userRole == null) {
            log.warn("User role not found in request attributes");
            return ResponseEntity.status(403).body(Map.of("error", "Access denied: insufficient permissions"));
        }

        // Get required role from annotation
        RequiredRole annotation = getRequiredRoleAnnotation(joinPoint);
        Role requiredRole = annotation.value();

        if (!userRole.hasPermissionLevel(requiredRole)) {
            log.warn("Access denied: User with role {} attempted to access endpoint requiring role {}", 
                    userRole, requiredRole);
            return ResponseEntity.status(403).body(Map.of("error", "Access denied: insufficient permissions"));
        }

        // Proceed if user has the required Role Permission
        return joinPoint.proceed();
    }

    private RequiredRole getRequiredRoleAnnotation(ProceedingJoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // Check if the method has the annotation
        RequiredRole annotation = method.getAnnotation(RequiredRole.class);

        // If not, check if the class has the annotation
        if (annotation == null) {
            annotation = method.getDeclaringClass().getAnnotation(RequiredRole.class);
        }

        return annotation;
    }

}
