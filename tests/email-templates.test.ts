import test from 'node:test';
import assert from 'node:assert/strict';
import {formatEmailValidity,renderRegistrationEmail,renderOtpEmail,renderPasswordResetEmail,renderPasswordChangedEmail,renderEmailVerifyEmail,renderEmailChangedEmail,renderTestEmail} from '../src/emailTemplates.js';

const sent=Date.parse('2030-01-01T00:00:00Z');
for(const [seconds,expected] of [
  [72*3600-5,'Expires in about 3 days.'],[48*3600-30,'Expires in about 2 days.'],
  [53*3600+20*60,'Expires in about 53 hours.'],[25*3600+10*60,'Expires in about 25 hours.'],
  [105*60,'Expires in about 1 hour 45 minutes.'],[17*60+20,'Expires in about 18 minutes.'],
  [60,'Expires in about 1 minute.'],[40,'Expires in less than a minute.'],[0,'This link has expired.'],
] as const) test('email validity describes remaining send-time duration: '+seconds,()=>{
  assert.equal(formatEmailValidity(new Date(sent+seconds*1000).toISOString(),sent),expected);
});
test('resending or changing display timezone never invents a new expiry window',()=>{
  const deadline='2030-01-04T00:00:00Z';
  assert.equal(formatEmailValidity(deadline,sent),'Expires in about 3 days.');
  assert.equal(formatEmailValidity(deadline,sent+20*3600*1000),'Expires in about 52 hours.');
  assert.equal(formatEmailValidity('2030-01-03T16:00:00-08:00',sent+20*3600*1000),'Expires in about 52 hours.');
  assert.throws(()=>formatEmailValidity('bad',sent),/Invalid email expiry/);
});
test('admin invitation and public signup have distinct reason, heading and action',()=>{
  const common={siteName:'Example Account',link:'https://account.example.test/register?token=synthetic',minutes:30};
  const admin=renderRegistrationEmail({...common,origin:'admin'}),signup=renderRegistrationEmail({...common,origin:'public'});
  assert.equal(admin.subject,"You're invited to join Example Account");
  assert.match(admin.text,/An administrator has invited you/);assert.match(admin.html,/Accept invitation/);
  assert.doesNotMatch(signup.text,/administrator|invitation/);assert.match(signup.html,/Create account/);
  for(const m of [admin,signup]){
    assert.equal((m.html.match(/can ignore this email/g)||[]).length,1);
    assert.equal((m.html.match(/href=/g)||[]).length,1,'one action, no repeated long-token URL');
    assert.doesNotMatch(m.html,/resending|UTC|GMT|<script|<img|@font-face/i);
  }
});
test('registration and email change use their fixed deadline rather than the nominal minutes on resend',()=>{
  const deadline=new Date(Date.now()+17*60*1000).toISOString();
  for(const m of [renderRegistrationEmail({siteName:'Example',link:'https://example.test/register',expiresAt:deadline,minutes:4320}),renderEmailVerifyEmail({siteName:'Example',link:'https://example.test/verify',kind:'change',expiresAt:deadline,minutes:30})]){
    assert.match(m.html,/Expires in about 17 minutes/);
    assert.match(m.text,/Expires in about 17 minutes/);
    assert.doesNotMatch(m.text,/3 days|30 minutes|2030|UTC|GMT/);
  }
});
test('dynamic names, codes and link attributes stay escaped in HTML',()=>{
  const value='<script>alert("x")</script>&';
  const email=renderRegistrationEmail({siteName:value,origin:'admin',link:'https://example.test/?a="x"&b=1',minutes:30});
  assert.doesNotMatch(email.html,/<script>/);assert.match(email.html,/&lt;script&gt;/);
  assert.match(email.html,/a=&quot;x&quot;&amp;b=1/);
  const code=renderOtpEmail({siteName:'Example',code:value,minutes:5});assert.doesNotMatch(code.html,/<script>/);
  assert.match(renderPasswordResetEmail({siteName:'Example',username:value,link:'https://example.test/reset',minutes:10}).html,/&lt;script&gt;/);
});
test('security notifications retain action without an ignore disclaimer or a false reset-link claim',()=>{
  const password=renderPasswordChangedEmail({siteName:'Example',username:'learner',portalUrl:'https://account.example.test'});
  const email=renderEmailChangedEmail({siteName:'Example',username:'learner',newEmailMasked:'p***@example.test',portalUrl:'https://account.example.test'});
  for(const m of [password,email]){assert.doesNotMatch(m.html,/ignore this email|using a reset link|Other sessions/);assert.match(m.text,/Review account security/);assert.match(m.html,/\/security/);assert.match(m.text,/contact your administrator/);assert.match(m.html,/contact your administrator/);}
  assert.match(email.text,/contact your administrator/);
  assert.doesNotMatch(renderOtpEmail({siteName:'Example',code:'123456',minutes:5}).text,/password still protects/);
});
test('all mail families share mobile-readable inline fallbacks and preserve plain-text actions',()=>{
  const mails=[renderRegistrationEmail({siteName:'Example',link:'https://example.test/register',minutes:30}),renderOtpEmail({siteName:'Example',code:'123456',minutes:5}),renderPasswordResetEmail({siteName:'Example',username:'learner',link:'https://example.test/reset',minutes:10}),renderPasswordChangedEmail({siteName:'Example',username:'learner',portalUrl:'https://example.test'}),renderEmailVerifyEmail({siteName:'Example',link:'https://example.test/verify',minutes:30,kind:'confirm'}),renderEmailChangedEmail({siteName:'Example',username:'learner',newEmailMasked:'p***@example.test',portalUrl:'https://example.test'}),renderTestEmail({siteName:'Example'})];
  for(const m of mails){assert.match(m.html,/max-width:480px/);assert.match(m.html,/font-size:16px/);assert.match(m.html,/role="presentation"/);assert.match(m.html,/prefers-color-scheme:dark/);assert.ok(m.text.startsWith('Example\n'));assert.doesNotMatch(m.text,/<table|<style/);}
});
