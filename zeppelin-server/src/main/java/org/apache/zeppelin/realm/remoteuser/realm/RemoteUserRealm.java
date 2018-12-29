/**
 * Copyright 2017, Yahoo Inc.
  * Released under Apache 2.0 License.  See file LICENSE in project root.
 */

package org.apache.zeppelin.realm.remoteuser.realm;

import java.util.Set;

import org.apache.zeppelin.realm.remoteuser.filter.RemoteUserAuthenticationToken;
import org.apache.zeppelin.realm.remoteuser.entity.RemoteUser;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;

import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;


public class RemoteUserRealm extends AuthorizingRealm {

    @Override
    public Class getAuthenticationTokenClass() {
        return RemoteUserAuthenticationToken.class;
    }

  
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
        RemoteUserAuthenticationToken remoteUserAuthenticationToken = (RemoteUserAuthenticationToken) token;
        String userId = remoteUserAuthenticationToken.getUserId();
        Set<String> roles = remoteUserAuthenticationToken.getRoles();

        if (userId != null) {
            RemoteUser remoteUserUser = new RemoteUser(userId, roles);
            SimpleAccount account = new SimpleAccount(remoteUserUser, remoteUserAuthenticationToken.getToken(), getName());
            account.addRole(roles);
            return account;
        } else {
            return null;
        }
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return new SimpleAuthorizationInfo(((RemoteUser) principals.getPrimaryPrincipal()).getRoles());
    }

 
    public AuthorizationInfo queryForAuthorizationInfo(final PrincipalCollection principals) {
      return  getAuthorizationInfo(principals);
    }    

}
