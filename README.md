# Login Server
로그인 서버

## 🖥️ 프로젝트 소개
asdfasdfsdfasdfasdf
<br>

## 주요 기능
- 로그인 인증 처리
- JWT 토큰 생성 및 JWE로의 암호화
- Cookie를 이용한 암호화된 토큰 저장
- JWT 토큰 재발급
- 사용자 인증 갱신

## 인증 및 권한 부여 절차
### 로그인 및 토큰 발급
1. **사용자 로그인 요청**: 사용자는 로그인 페이지에서 ID와 패스워드를 입력하여 로그인을 요청합니다.
2. **토큰 생성 및 암호화**: 로그인 검증 후, JWT 토큰을 생성하고 이를 JWE로 암호화합니다.
3. **토큰 저장**: 암호화된 토큰은 사용자의 Cookie에 저장되어, 다른 MSA 서버에서 사용됩니다.
4. **토큰 재발급**: '/refresh' 경로를 통해 만료된 토큰에 대한 재발급 요청을 처리합니다.

## 🕰️ 개발 기간
* -

### 🧑‍🤝‍🧑 맴버구성
 - 팀장  : 오수민 - ASDF
 - 팀원  : 김아영
 
### ⚙️ 개발 환경
- `Java 17`
- `JDK 17.0.6`
- **IDE** : STS 4.17.2, VSCode, IntelliJ IDEA
- **Framework** : Spring Boot 3.x
- **Database** : MySQL
- **ORM** : Mybatis

### 프로젝트 파일 구조
<details>
<summary>BACKEND</summary>

```plaintext
LOGIN-SERVER\SRC\MAIN
📦java
 ┗ 📂jj
 ┃ ┗ 📂stella
 ┃ ┃ ┣ 📂config
 ┃ ┃ ┃ ┣ 📜CookieConfig.java
 ┃ ┃ ┃ ┣ 📜DBConfig.java
 ┃ ┃ ┃ ┣ 📜RedisConfig.java
 ┃ ┃ ┃ ┣ 📜ScheduleConfig.java
 ┃ ┃ ┃ ┣ 📜ScheduleLockConfig.java
 ┃ ┃ ┃ ┣ 📜SecurityConfig.java
 ┃ ┃ ┃ ┗ 📜WebMvcConfig.java
 ┃ ┃ ┣ 📂controller
 ┃ ┃ ┃ ┗ 📜MainController.java
 ┃ ┃ ┣ 📂entity
 ┃ ┃ ┃ ┣ 📂dto
 ┃ ┃ ┃ ┃ ┣ 📜RedisDto.java
 ┃ ┃ ┃ ┃ ┣ 📜RefreshTokenDto.java
 ┃ ┃ ┃ ┃ ┣ 📜ReissueDto.java
 ┃ ┃ ┃ ┃ ┗ 📜UserDto.java
 ┃ ┃ ┃ ┗ 📂vo
 ┃ ┃ ┃ ┃ ┗ 📜UserVo.java
 ┃ ┃ ┣ 📂filter
 ┃ ┃ ┃ ┣ 📂auth
 ┃ ┃ ┃ ┃ ┣ 📜AuthDetails.java
 ┃ ┃ ┃ ┃ ┣ 📜AuthDetailsSource.java
 ┃ ┃ ┃ ┃ ┣ 📜AuthFailure.java
 ┃ ┃ ┃ ┃ ┣ 📜AuthLogout.java
 ┃ ┃ ┃ ┃ ┣ 📜AuthProvider.java
 ┃ ┃ ┃ ┃ ┗ 📜AuthSuccess.java
 ┃ ┃ ┃ ┣ 📂csrf
 ┃ ┃ ┃ ┃ ┣ 📜Csrf.java
 ┃ ┃ ┃ ┃ ┣ 📜CsrfHandler.java
 ┃ ┃ ┃ ┃ ┗ 📜CsrfRepository.java
 ┃ ┃ ┃ ┣ 📂jwt
 ┃ ┃ ┃ ┃ ┗ 📜JwtIssue.java
 ┃ ┃ ┃ ┣ 📜Redirect.java
 ┃ ┃ ┃ ┗ 📜TrailingSlash.java
 ┃ ┃ ┣ 📂properties
 ┃ ┃ ┃ ┣ 📜AuthProperties.java
 ┃ ┃ ┃ ┗ 📜ServerProperties.java
 ┃ ┃ ┣ 📂repository
 ┃ ┃ ┃ ┣ 📂dao
 ┃ ┃ ┃ ┃ ┣ 📜CommonDao.java
 ┃ ┃ ┃ ┃ ┗ 📜CommonDaoImpl.java
 ┃ ┃ ┃ ┗ 📂service
 ┃ ┃ ┃ ┃ ┣ 📜CommonService.java
 ┃ ┃ ┃ ┃ ┣ 📜CommonServiceImpl.java
 ┃ ┃ ┃ ┃ ┗ 📜RedisService.java
 ┃ ┃ ┣ 📂util
 ┃ ┃ ┃ ┣ 📜CookieUtil.java
 ┃ ┃ ┃ ┣ 📜RedisLog.java
 ┃ ┃ ┃ ┣ 📜RedisUtil.java
 ┃ ┃ ┃ ┣ 📜SHA256.java
 ┃ ┃ ┃ ┗ 📜Verification.java
 ┃ ┃ ┗ 📜Application.java
```
</details>

<details>
<summary>FRONTEND</summary>

```plaintext
LOGIN-SERVER\SRC\MAIN\RESOURCES
📦static
 ┣ 📂style
 ┃ ┣ 📂card
 ┃ ┃ ┣ 📜_index.scss
 ┃ ┃ ┗ 📜_settings.scss
 ┃ ┣ 📜animation.scss
 ┃ ┣ 📜breakpoint.scss
 ┃ ┣ 📜global.scss
 ┃ ┗ 📜main.scss
 ┗ 📂ts
 ┃ ┣ 📂component
 ┃ ┃ ┣ 📂common
 ┃ ┃ ┃ ┣ 📂alert
 ┃ ┃ ┃ ┃ ┣ 📂Error
 ┃ ┃ ┃ ┃ ┃ ┗ 📜index.ts
 ┃ ┃ ┃ ┃ ┣ 📂Success
 ┃ ┃ ┃ ┃ ┃ ┗ 📜index.ts
 ┃ ┃ ┃ ┃ ┣ 📂Warning
 ┃ ┃ ┃ ┃ ┃ ┗ 📜index.ts
 ┃ ┃ ┃ ┃ ┗ 📜index.ts
 ┃ ┃ ┃ ┣ 📂background
 ┃ ┃ ┃ ┃ ┣ 📂Snow
 ┃ ┃ ┃ ┃ ┃ ┣ 📜index.ts
 ┃ ┃ ┃ ┃ ┃ ┗ 📜Snow.tsx
 ┃ ┃ ┃ ┃ ┣ 📂Stars
 ┃ ┃ ┃ ┃ ┃ ┣ 📜index.ts
 ┃ ┃ ┃ ┃ ┃ ┗ 📜Stars.tsx
 ┃ ┃ ┃ ┃ ┗ 📜index.ts
 ┃ ┃ ┃ ┣ 📂input
 ┃ ┃ ┃ ┃ ┣ 📂Password
 ┃ ┃ ┃ ┃ ┃ ┣ 📜index.ts
 ┃ ┃ ┃ ┃ ┃ ┗ 📜Password.tsx
 ┃ ┃ ┃ ┃ ┣ 📂String
 ┃ ┃ ┃ ┃ ┃ ┣ 📜index.ts
 ┃ ┃ ┃ ┃ ┃ ┗ 📜String.tsx
 ┃ ┃ ┃ ┃ ┣ 📜index.ts
 ┃ ┃ ┃ ┃ ┗ 📜InputPassword.tsx
 ┃ ┃ ┃ ┗ 📜DarkMode.tsx
 ┃ ┃ ┗ 📂view
 ┃ ┃ ┃ ┗ 📜Main.tsx
 ┃ ┣ 📂config
 ┃ ┃ ┗ 📂type
 ┃ ┃ ┃ ┗ 📜index.ts
 ┃ ┗ 📜App.tsx
```
</details>
