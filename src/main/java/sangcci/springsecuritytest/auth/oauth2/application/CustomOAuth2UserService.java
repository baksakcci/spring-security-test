package sangcci.springsecuritytest.auth.oauth2.application;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sangcci.springsecuritytest.auth.oauth2.dto.OAuth2UserInfo;
import sangcci.springsecuritytest.auth.dto.PrincipalDetails;
import sangcci.springsecuritytest.auth.oauth2.exception.UnsupportedProviderException;
import sangcci.springsecuritytest.user.domain.Member;
import sangcci.springsecuritytest.user.infra.MemberJpaRepository;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final MemberJpaRepository memberJpaRepository;

    @Transactional
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 1 - OAuth2 Client를 사용하여 Auth Server로부터 유저 정보 가져오기
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 2 - socialType 가져오기(third-party id)
        String socialType = userRequest.getClientRegistration().getRegistrationId();
        log.info("socialType: {}", socialType);

        // 3 - 유저 정보 dto 생성(Auth Server로부터 받은 attributes들을 토대로 유저 정보 DTO를 만듬)
        OAuth2UserInfo oAuth2UserInfo;
        if (socialType.equals("google")) {
            oAuth2UserInfo = OAuth2UserInfo.ofGoogle(oAuth2User.getAttributes());
        } else if (socialType.equals("kakao")) {
            oAuth2UserInfo = OAuth2UserInfo.ofKakao(oAuth2User.getAttributes());
        }else {
            throw new UnsupportedProviderException();
        }

        // 4 - 회원 존재 확인, 없다면 임시 회원 정보 생성
        Member member = memberJpaRepository.findByEmail(oAuth2UserInfo.email())
                .orElseGet(() ->
                    Member.createTemporary(
                            oAuth2UserInfo.email(),
                            oAuth2UserInfo.nickname(),
                            oAuth2UserInfo.loginProvider(),
                            oAuth2UserInfo.providerId()
                ));
        memberJpaRepository.save(member); // 임시 회원 포함 저장

        // 5 - OAuth2User로 반환
        return new PrincipalDetails(member, oAuth2User.getAttributes());
    }
}
