package com.upgrad.stackoverflow.service.business;

import com.upgrad.stackoverflow.service.common.JwtTokenProvider;
import com.upgrad.stackoverflow.service.dao.UserDao;
import com.upgrad.stackoverflow.service.entity.UserAuthEntity;
import com.upgrad.stackoverflow.service.entity.UserEntity;
import com.upgrad.stackoverflow.service.exception.AuthenticationFailedException;
import com.upgrad.stackoverflow.service.exception.SignOutRestrictedException;
import com.upgrad.stackoverflow.service.exception.SignUpRestrictedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;

@Service
public class UserBusinessService {

    @Autowired
    private UserDao userDao;

    @Autowired
    private PasswordCryptographyProvider passwordCryptographyProvider;

    private final Logger LOGGER = LoggerFactory.getLogger(UserBusinessService.class);

    /**
     * The method implements the business logic for signup endpoint.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public UserEntity signup(UserEntity userEntity) throws SignUpRestrictedException {
        LOGGER.info("In Signup Service method, encrypting password.");
        String[] encryptedText = passwordCryptographyProvider.encrypt(userEntity.getPassword());
        userEntity.setSalt(encryptedText[0]);
        userEntity.setPassword(encryptedText[1]);
        LOGGER.info("Password Encryption Successful, checking if user already exists.");
        if(userDao.getUserByUsername(userEntity.getUserName())!=null){
            throw new SignUpRestrictedException("SGR-001", "Try any other Username, this Username has already been taken");
        }
        if(userDao.getUserByEmail(userEntity.getEmail())!=null){
            throw new SignUpRestrictedException("SGR-002", "This user has already been registered, try with any other emailId");
        }
        return userDao.createUser(userEntity);
    }

    /**
     * The method implements the business logic for signin endpoint.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public UserAuthEntity authenticate(String username, String password) throws AuthenticationFailedException {
        LOGGER.info("In signin Service, getting user from database");
        UserEntity userEntity = userDao.getUserByUsername(username);
        if(userEntity==null){
            throw new AuthenticationFailedException("ATH-001","This username does not exist");
        }
        LOGGER.info("Checking Password");
        final String encryptedPassword = passwordCryptographyProvider.encrypt(password, userEntity.getSalt());
        if(encryptedPassword.equals(userEntity.getPassword())){
            JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(encryptedPassword);
            UserAuthEntity userAuthToken = new UserAuthEntity();
            userAuthToken.setUser(userEntity);
            final ZonedDateTime now = ZonedDateTime.now();
            final ZonedDateTime expiresAt = now.plusHours(8);
            userAuthToken.setAccessToken(jwtTokenProvider.generateToken(userEntity.getUuid(), now, expiresAt));
            userAuthToken.setLoginAt(now);
            userAuthToken.setExpiresAt(expiresAt);
            userAuthToken.setUuid(userEntity.getUuid());
            LOGGER.info("Creating and saving accessToken");
            userDao.createUserAuth(userAuthToken);
//            userDao.updateUser(userEntity);

            return userAuthToken;
        }
        else{
            throw new AuthenticationFailedException("ATH-002", "Password failed");
        }
    }

    /**
     * The method implements the business logic for signout endpoint.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public UserAuthEntity signout(String authorization) throws SignOutRestrictedException {
        LOGGER.info("In signout Service");
        if(authorization==null)
            throw new SignOutRestrictedException("SGR-001", "User is not Signed in");
        UserAuthEntity userAuthEntity = userDao.getUserAuthByAccesstoken(authorization);
        if(userAuthEntity==null)
            throw new SignOutRestrictedException("SGR-001", "User is not Signed in");
        if(userAuthEntity.getLogoutAt()!=null)
            throw new SignOutRestrictedException("SGR-001","User is not Signed in");

        final ZonedDateTime now = ZonedDateTime.now();
        LOGGER.info("Setting Logout time");
        userAuthEntity.setLogoutAt(now);
        return userDao.updateUserAuth(userAuthEntity);
    }
}
