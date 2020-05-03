package com.upgrad.stackoverflow.api.controller;

import com.upgrad.stackoverflow.api.model.SigninResponse;
import com.upgrad.stackoverflow.api.model.SignoutResponse;
import com.upgrad.stackoverflow.api.model.SignupUserRequest;
import com.upgrad.stackoverflow.api.model.SignupUserResponse;
import com.upgrad.stackoverflow.service.business.UserBusinessService;
import com.upgrad.stackoverflow.service.entity.UserAuthEntity;
import com.upgrad.stackoverflow.service.entity.UserEntity;
import com.upgrad.stackoverflow.service.exception.AuthenticationFailedException;
import com.upgrad.stackoverflow.service.exception.SignOutRestrictedException;
import com.upgrad.stackoverflow.service.exception.SignUpRestrictedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.UUID;
@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserBusinessService userBusinessService;

    private final Logger LOGGER = LoggerFactory.getLogger(UserController.class);

    /**
     * A controller method for user signup.
     *
     * @param signupUserRequest - This argument contains all the attributes required to store user details in the database.
     * @return - ResponseEntity<SignupUserResponse> type object along with Http status CREATED.
     * @throws SignUpRestrictedException
     */
    @PostMapping("/signup")
    public ResponseEntity<SignupUserResponse> signup(@RequestBody SignupUserRequest signupUserRequest) throws SignUpRestrictedException {
        LOGGER.info("In signup method.");
        final UserEntity userEntity = new UserEntity();
        userEntity.setUuid(UUID.randomUUID().toString());
        userEntity.setFirstName(signupUserRequest.getFirstName());
        userEntity.setLastName(signupUserRequest.getLastName());
        userEntity.setEmail(signupUserRequest.getEmailAddress());
        userEntity.setPassword(signupUserRequest.getPassword());
        userEntity.setUserName(signupUserRequest.getUserName());
        userEntity.setSalt("1234abc");
        userEntity.setCountry(signupUserRequest.getCountry());
        userEntity.setContactNumber(signupUserRequest.getContactNumber());
        userEntity.setAboutMe(signupUserRequest.getAboutMe());
        userEntity.setDob(signupUserRequest.getDob());
        userEntity.setRole("user");
        LOGGER.info("The User Info is {}",userEntity);
        final UserEntity createdUserEntity = userBusinessService.signup(userEntity);
        SignupUserResponse userResponse = new SignupUserResponse().id(createdUserEntity.getUuid()).status("REGISTERED");
        LOGGER.info("Signup Successful");
        return new ResponseEntity<SignupUserResponse>(userResponse,HttpStatus.CREATED);
    }

    /**
     * A controller method for user authentication.
     *
     * @param authorization - A field in the request header which contains the user credentials as Basic authentication.
     * @return - ResponseEntity<SigninResponse> type object along with Http status OK.
     * @throws AuthenticationFailedException
     */

    @RequestMapping(method = RequestMethod.POST, path = "/signin", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<SigninResponse> authentication(@RequestHeader("authorization") final String authorization) throws AuthenticationFailedException{
        LOGGER.info("In Signin Controller method, Decoding username and password");
        byte[] decode = Base64.getDecoder().decode(authorization.split("Basic ")[1]);
        String decodedText = new String(decode);
        String[] decodedArray = decodedText.split(":");
        LOGGER.info("Calling Business service to authenticate");
        UserAuthEntity userAuthToken = userBusinessService.authenticate(decodedArray[0],decodedArray[1]);
        UserEntity user = userAuthToken.getUser();
        LOGGER.info("Signin Successful");
        SigninResponse signinResponse = new SigninResponse().id(user.getUuid()).message("Successfully Signedin");
        HttpHeaders header= new HttpHeaders();
        header.add("access-token", userAuthToken.getAccessToken());
        return new ResponseEntity<SigninResponse>(signinResponse, header,HttpStatus.OK);
    }

    /**
     * A controller method for user signout.
     *
     * @param authorization - A field in the request header which contains the JWT token.
     * @return - ResponseEntity<SignoutResponse> type object along with Http status OK.
     * @throws SignOutRestrictedException
     */

    @RequestMapping(method = RequestMethod.POST, path = "/signout", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<SignoutResponse> signout(@RequestHeader("authorization") final String authorization) throws SignOutRestrictedException{
        LOGGER.info("In Signout method");
        UserAuthEntity userAuthEntity = userBusinessService.signout(authorization);

        UserEntity user = userAuthEntity.getUser();
        LOGGER.info("Signout Successful");
        SignoutResponse signoutResponse = new SignoutResponse().id(user.getUuid()).message("Successfully Signed out");
        return new ResponseEntity<SignoutResponse>(signoutResponse,HttpStatus.OK);

    }

}
