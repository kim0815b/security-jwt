package com.kim0815.securityjwt.repository;

import com.kim0815.securityjwt.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByUsername(String username);
    Boolean existsByUsername(String username);
}
