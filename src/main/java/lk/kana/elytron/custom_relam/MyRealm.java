package lk.kana.elytron.custom_relam;


import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.jboss.logging.Logger;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.jdbc.mapper.AttributeMapper;
import org.wildfly.security.auth.realm.jdbc.mapper.PasswordKeyMapper;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.Attributes.Entry;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.auth.realm.jdbc.JdbcSecurityRealm;
//import org.wildfly.security.auth.realm.jdbc.JdbcSecurityRealm.JdbcRealmIdentity;
import org.wildfly.security.evidence.PasswordGuessEvidence;
//import org.wildfly.security.password.interfaces.ClearPassword;

public class MyRealm implements SecurityRealm {

	 private String data_source;
	
	 private String principalQuery = "SELECT PASSWORD FROM USERS WHERE USERNAME = ?";
	 private String rolesQuery = "SELECT R.NAME, 'Roles' FROM USERS_ROLES UR INNER JOIN ROLES R ON R.ID = UR.ROLE_ID INNER JOIN USERS U ON U.ID = UR.USER_ID WHERE U.USERNAME = ?";
	 private Logger log = Logger.getLogger(this.getClass());
	 
	 private DataSource ds;
	 
	 public MyRealm(){
//		 connection = ds.getConnection();
	}

	 
	// receiving configuration from subsystem to this to work need to implement Configurable
	public void initialize(Map<String, String> configuration) {

		data_source = configuration.get("data-source");
		System.out.println("MyRealm initialized with data-source = " + data_source);


	}

	
	public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, 
													String algorithmName,
													AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
		// this realm does not allow acquiring credentials
		log.infof("getCredentialAcquireSupport %s, %s, %s", credentialType, algorithmName, parameterSpec);
		return SupportLevel.UNSUPPORTED;

	}

	
	// this realm will be able to verify password evidences
	public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName)
			throws RealmUnavailableException {

		log.infof("getEvidenceVerifySupport : %s %s", evidenceType, algorithmName);
		return PasswordGuessEvidence.class.isAssignableFrom(evidenceType) ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
		

	}

	
	public RealmIdentity getRealmIdentity(final Principal principal) throws RealmUnavailableException {
		log.info("================================================================");


		if (! (principal instanceof NamePrincipal)) {
            return RealmIdentity.NON_EXISTENT;
        }
        return new MyRealmIdentity(principal.getName());

//		return RealmIdentity.NON_EXISTENT;
	}
	
	
	
	//-------------------------------------------------------------------------------------
	private DataSource getDataSource() throws RealmUnavailableException{
		/*
		 * The DS access needs to do in this level and not during realm initialization 
		 * other wise we get into issue with server startup.
		 * 
		 * javax.naming.NoInitialContextException: Need to specify class name in environment or system property, 
		 * or as an applet parameter, or in an application resource file:  java.naming.factory.initial
		 */
		
		if (this.ds != null) {
			return this.ds;
		}

		try {
			//for this to work make sure the use-java-context="true" is set in xml
			Context ctx = new InitialContext();
			this.ds = (DataSource)ctx.lookup("java:jboss/datasources/ServletSecurityDS");
			return this.ds;
		} catch (NamingException e) {
			e.printStackTrace();
			throw new RealmUnavailableException();
		}
		
	}
	

	private class MyRealmIdentity implements RealmIdentity {
		
		private final String name;
		private JdbcIdentity identity;

		
		public MyRealmIdentity(String name) {
			
			this.name = name;

		}
		
        public Principal getRealmIdentityPrincipal() {
            return new NamePrincipal(name);
        }

        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType,
                String algorithmName, AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        
        	
        	JdbcIdentity identity = getIdentity();
            if (identity != null) {
                return identity.identityCredentials.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
            }

        	return SupportLevel.UNSUPPORTED;
        }

        
        
        public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
        	return getCredential(credentialType, null);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {

        	return getCredential(credentialType, algorithmName, null);
        }
        
        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {

            JdbcIdentity identity = getIdentity();
            if (identity != null) {
                return identity.identityCredentials.getCredential(credentialType, algorithmName);
            }

            return null;
        }

        
        public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName)
                throws RealmUnavailableException {
            return PasswordGuessEvidence.class.isAssignableFrom(evidenceType) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
        }

        // evidence will be accepted if it is password "password123"
        public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {

        	
        	JdbcIdentity identity = getIdentity();
            if (identity != null) {
                return identity.identityCredentials.verify(evidence);
            }

        	//realmIdentity.verifyEvidence(new PasswordGuessEvidence(userPassword.toCharArray())
        	
//            if (evidence instanceof PasswordGuessEvidence) {
//                PasswordGuessEvidence guess = (PasswordGuessEvidence) evidence;
//                try {
//                    return Arrays.equals("password123".toCharArray(), guess.getGuess());
//
//                } finally {
//                    guess.destroy();
//                }
//            }

            return false;
        }

        public boolean exists() throws RealmUnavailableException {
            return getIdentity() != null;
        }

        

        // this output is used by the RoleDecoder, from-roles-attribute
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {

        	if (!exists()) {
                return AuthorizationIdentity.EMPTY;
            }

        	// make the role to be admin.
        	MapAttributes attributes = new MapAttributes();
        	attributes.addFirst("roles", "Admin");

        	log.info("xxxxxxxx this.identity.attributes xxxxxxxxxxx  "+ this.identity.attributes);
        	
//            return AuthorizationIdentity.basicIdentity(this.identity.attributes);
            return AuthorizationIdentity.basicIdentity(attributes);
        }

        
        
        
        // a sample identity to handle user data.
        private JdbcIdentity getIdentity() throws RealmUnavailableException {

        	if (this.identity == null) {
				
        		log.info("yyyyyyyyyyyyyyyyyy  getIdentity()  yyyyyyyyyyyyyyyyyyyyy");
			
	        	
	        	MapAttributes attributes = new MapAttributes();
	            IdentityCredentials credentials = IdentityCredentials.NONE;
		
	            PasswordKeyMapper passwordKeyMapper = PasswordKeyMapper.builder()
			            .setDefaultAlgorithm(ClearPassword.ALGORITHM_CLEAR)
			            .setHashColumn(1)
			            .build();
	
				JdbcSecurityRealm securityItendityRealm = JdbcSecurityRealm.builder()
															 .principalQuery(principalQuery)
																.withMapper(passwordKeyMapper)
																.from(getDataSource()) // ?? how to get he datasource !!!
																.build();

				JdbcSecurityRealm securityItendityRoleRealm = JdbcSecurityRealm.builder()
															.principalQuery("SELECT R.NAME, 'Roles' FROM USERS_ROLES UR INNER JOIN ROLES R ON R.ID = UR.ROLE_ID INNER JOIN USERS U ON U.ID = UR.USER_ID WHERE U.USERNAME = ?")
											                    .withMapper(new AttributeMapper(1, "roles"))
											                    .from(getDataSource())
															.build();
				
				log.info("this.getRealmIdentityPrincipal() "+ this.getRealmIdentityPrincipal().getName() );
				RealmIdentity identity = securityItendityRealm.getRealmIdentity(this.getRealmIdentityPrincipal());
	
				RealmIdentity identityRole = securityItendityRoleRealm.getRealmIdentity(this.getRealmIdentityPrincipal());
				//is there a user with the given name 
				if (identity.exists()) {
					
					Credential pass = identity.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR);
					credentials = credentials.withCredential(pass);

					// get attributes will transfer the roles associated with the user
					log.info("list ...... --> " + identityRole.getAttributes());
					if (identityRole.getAttributes() != null) {
						
					
						for (Entry entry :  identityRole.getAttributes().entries()) {
							System.out.println(entry.toString());
						}
						
					}
					
					this.identity= new JdbcIdentity(identityRole.getAttributes(), credentials);
					
				}else {
					log.warn("user does not exists...");
				}
        	}
        	return this.identity;

			
        }
        
        
        private class JdbcIdentity {

            private final Attributes attributes;
            private final IdentityCredentials identityCredentials;

            JdbcIdentity(Attributes attributes, IdentityCredentials identityCredentials) {
                this.attributes = attributes;
                this.identityCredentials = identityCredentials;
            }
        }
        
    }
	
}
