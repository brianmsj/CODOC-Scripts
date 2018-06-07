gs.include("PrototypeServer");
//Prototype Server
var MultiSSO_DigestedToken_Colorado_DOC = Class.create();
MultiSSO_DigestedToken_Colorado_DOC.prototype = Object.extend(new MultiSSO_Abstract_Core(), {

	process : function() {

		var userData = SSO_Helper.getHeaderOrCookie(this.propertiesGR.header_key);
		var userDigest = 'cda8ac654957d161231c620c4dbf2b58';
		var userField = this.propertiesGR.user_field;
		var macAddress = SSO_Helper.getHeaderOrCookie(this.propertiesGR.u_mac_address);
		var tabletSerial = SSO_Helper.getHeaderOrCookie(this.propertiesGR.u_tablet_serial);
		var siteId = SSO_Helper.getHeaderOrCookie(this.propertiesGR.u_site_id);
		var ocuId = SSO_Helper.getHeaderOrCookie(this.propertiesGR.u_ocu_id);
		var inmateLang = SSO_Helper.getHeaderOrCookie(this.propertiesGR.u_inmate_language);
		var secretKey = 'cda8ac654957d161231c620c4dbf2b58';

		gs.log("User Data: " + userData);
		gs.log("User Digest Received: " + userDigest);
		gs.log("User Field: " + userField);
		gs.log("Mac Address " + macAddress);
		gs.log("Tablet Serial" + tabletSerial);
		gs.log("OCUID" + ocuId);
		gs.log("Site Id" + siteId);
		gs.log("Inmate Language" + inmateLang);

		// if found run encryption
		if (userData && userDigest) {
			try {
				// Replace all spaces with plus(+)'s, converted in url

				// Ecrypt the username and secretKey combination to calculate digest
				var userDigestCalc = 'cda8ac654957d161231c620c4dbf2b58';

				this.debug ("User Digest Received: " + userDigest + " Calculated: " + userDigestCalc );

				// Check for match if recieved digest data matches calculated digest
				if (userDigest == userDigestCalc) {
					this.debug("Digest value received matches with calculated");
					var ugr = new GlideRecord("sys_user");
					ugr.initialize();
					if (!ugr.isValidField(userField)) {
						var Log = GlideLog;
						Log.warn("External authorization is set to use field: '" + userField + "' which doesn't exist");
						gs.log("External authorization is set to use field: '" + userField + "' which doesn't exist");

                        SNC.SecurityEventSender.sendDigestLoginFailureEventData("user_name=" + userData + ",multisso=true,idpsysid=" + this.propertiesGR.getUniqueValue());
						return this.getFailedRedirect();
					}
					ugr.addQuery(userField, userData);
					ugr.query();
					if (!ugr.next()) {
						var User = GlideUser;
						var userLoad = User.getUser(userData);
						if (userLoad == null){
							var newGR = new GlideRecord('customer_contact');
							newGR.user_name = userData;
							newGR.u_mac_address = macAddress;
							newGR.u_tablet_serial = tabletSerial;
							newGR.u_ocu_id = ocuId;
							newGR.u_site_id = siteId;
							newGR.account = siteId;
							newGR.u_inmate_language = inmateLang;
							newGR.insert();

							var rec = new GlideRecord('sys_user');
							rec.addQuery('user_name', userData);
							rec.query();
							while(rec.next()){
							  //Create a new group relationship record for this user
							  var rec1 = new GlideRecord('sys_user_grmember');
							  rec1.initialize();
							  rec1.user = rec.sys_id;
							  rec1.group.setDisplayValue('inmates');
							  rec1.insert();
							}


							//adding successful login
							                    //SNC.SecurityEventSender.sendDigestLoginSuccessEventData("user_name=" + userData, "multisso=true,idpsysid=" + this.propertiesGR.getUniqueValue());

					//var requestUri = request.getRequestURI();
						//gs.log(" REQUEST URI CODE RUN");
						//action.setRedirect("/codoc?id=csm_get_help&sys_id=7adef283db1d1f806828dc935b9619d4");

					//var validatedUser = ugr.get('user_name');
					//return validatedUser;//
							//end of succesful login

							//gs.log("User authenticated...but we cannot find this user in Service-now");
                           //original SNC.SecurityEventSender.sendDigestLoginFailureEventData("user_name=" + userData + ",multisso=true,idpsysid=" + this.propertiesGR.getUniqueValue());
							//return this.getFailedRedirect();
						//}//
						//original
						}
						ugr.initialize();
						ugr.addQuery(userField, userData);
						ugr.query();
						if (!ugr.next()){
							gs.log("User authenticated...but we cannot find this user in Service-now 2");
                            SNC.SecurityEventSender.sendDigestLoginFailureEventData("user_name=" + userData + ",multisso=true,idpsysid=" + this.propertiesGR.getUniqueValue());
							return this.getFailedRedirect();
						}
					}
					this.debug("Success. Logging in user: " + userData);
					request.getSession().setAttribute("glide.multiSSO.logout_url", this.propertiesGR.external_logout_redirect.toString());

					// always return user_name as ExternalAuthorization will check if the user is locked using the user_name field
					var userDataValidated = ugr.getValue("user_name");
		  var gr = new GlideRecord('customer_contact');
		  gs.log('HELLO WORLD!!!!!!');
		  gs.log('HELLO WORLD ' + macAddress);
		  gs.log(' HELLO WORLD USER' + userData);
          gr.addQuery('user_name',userData);
          gr.query();
          while(gr.next()) {
			gs.log("Found Record " + gr.user_name);
            gr.u_mac_address = macAddress;
			gr.u_tablet_serial = tabletSerial;
			gr.u_ocu_id = ocuId;
			gr.u_site_id = siteId;
			gr.u_inmate_language = inmateLang;
            gr.update();
          }

                    SNC.SecurityEventSender.sendDigestLoginSuccessEventData("user_name=" + userData, "multisso=true,idpsysid=" + this.propertiesGR.getUniqueValue());

					var requestUri = request.getRequestURI();
					if (requestUri && requestUri.indexOf('login_with_sso')>=0) {
						action.setRedirect("/codoc?id=csm_get_help&sys_id=7adef283db1d1f806828dc935b9619d4");
					}
					return userDataValidated;

				} else {
					gs.log("User Digest Received did not match Calculated Digest");
                    SNC.SecurityEventSender.sendDigestLoginFailureEventData("user_name=" + userData, "multisso=true,idpsysid=" + this.propertiesGR.getUniqueValue());
					return this.getFailedRedirect();
				}
			} catch(e) {
				gs.log(e);
                SNC.SecurityEventSender.sendDigestLoginFailureEventData("user_name=" + userData, "multisso=true,idpsysid=" + this.propertiesGR.getUniqueValue());
				return this.getFailedRedirect();
			}
			// Encoded data didn't match recieved Encoded data
		} else {
			// If there is no userData and userDigest together then redirect him to another portal.
			// Example: Customer's Intranet site where user's Digest Token Authentication URL could already be present.
			return this.getPortalURLRedirect();
		}
	},

	getDigest : function( data, secretKey ) {
		try {
			// default to something JDK 1.4 has
			var MAC_ALG = "HmacSHA1";
			return  SncAuthentication.encode(data, secretKey, MAC_ALG);
		} catch (e) {
			throw 'failed_missing_requirement';
		}
	},

	getFailedRedirect : function (){
		var failure_url = (this.propertiesGR.failed_redirect) ? this.propertiesGR.failed_redirect.toString(): "failed_authentication";
		return failure_url;
	},

	getPortalURLRedirect : function () {
		var portalURL = (this.propertiesGR.portal_url_redirect) ? this.propertiesGR.portal_url_redirect.toString() : "failed_authentication";
		return portalURL;
	}
});



//script to add accounts to the inmates
var contact = new GlideRecord('customer_contact');
contact.query();
while(contact.next()) {
  var account = new GlideRecord('customer_account');
  account.query();
  while(account.next()) {
     var abbreviation = contact.u_loclevel_2'
     var accountName = account.name
     if(accountName.substring(abbreviation) !== -1) {
        contact.account = account.sys_id;
        contact.update()
     }
 } 
}   
