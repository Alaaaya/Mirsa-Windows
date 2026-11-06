export type Lang = "en" | "ar";
const en = {
 install:"Install Mirsa", appleId:"Apple ID email", password:"Password", show:"Show password", hide:"Hide password",
 connected:"iPhone connected", noDevice:"No iPhone found", plug:"Connect your iPhone with a USB cable", refresh:"Refresh",
 g1:"Unlock your iPhone and tap Trust on the prompt.", g2:"Enable Developer Mode: Settings, Privacy & Security, Developer Mode, then restart.", g3:"Keep the iPhone connected during install.",
 chooseDevice:"Choose device", pairTitle:"Export pairing file", pairSub:"Save your pairing file to use on another device or reinstall Mirsa.", export:"Export", exportFail:"Export failed",
 twoTitle:"Verification code", twoSub:"Enter the 6-digit code shown on your Apple devices.", cancel:"Cancel", confirm:"Confirm",
 s_login:"Sign in", s_download:"Download", s_install:"Install", s_open:"Open Mirsa", s_finish:"Finish",
 needFields:"Enter your Apple ID and password", needDevice:"Connect an iPhone first", tryAgain:"Try again", failed:"Something went wrong",
 doneTitle:"Mirsa is installed", doneSub:"Installed. Setup is not finished yet: open Mirsa on your iPhone first (a compatible Mirsa build), then press the button below to finish the secure sign-in.", finishBtn:"I opened Mirsa, finish sign-in",
 pairWarn:"Sensitive: this file grants access to your iPhone. Keep it local and never share it.", setupDone:"Setup complete", waiting:"Waiting for Mirsa on iPhone...", rejected:"Mirsa rejected the sign-in request. Reopen Mirsa and try again.", timeout:"Mirsa did not confirm in time. Keep Mirsa open on the iPhone, then press the button again.", certTitle:"Certificate limit reached", certSub:"Select certificates to revoke. Nothing is revoked without your choice.", s_pairing:"Pairing",
 privacy:"Your password is used once for sign-in and is never saved.", demo:"Browser preview, no device backend", lang:"العربية", done:"Done",
};
const ar:typeof en = {
 install:"تثبيت Mirsa", appleId:"إيميل Apple ID", password:"كلمة السر", show:"إظهار", hide:"إخفاء",
 connected:"الآيفون متصل", noDevice:"ما لقينا آيفون", plug:"وصّل الآيفون بكابل USB", refresh:"تحديث",
 g1:"افتح قفل الآيفون واضغط \"وثوق\" على الرسالة.", g2:"فعّل وضع المطور: الإعدادات، الخصوصية والأمان، وضع المطور، ثم أعد التشغيل.", g3:"خلي الآيفون موصول أثناء التثبيت.",
 chooseDevice:"اختر الجهاز", pairTitle:"تصدير ملف الاقتران", pairSub:"احفظ ملف الاقتران لتستعمله على جهاز آخر أو لإعادة تثبيت Mirsa.", export:"تصدير", exportFail:"فشل التصدير",
 twoTitle:"رمز التحقق", twoSub:"أدخل الرمز المكون من 6 أرقام الظاهر على أجهزة Apple.", cancel:"إلغاء", confirm:"تأكيد",
 s_login:"تسجيل الدخول", s_download:"تحميل", s_install:"تثبيت", s_open:"افتح Mirsa", s_finish:"إنهاء",
 needFields:"أدخل Apple ID وكلمة السر", needDevice:"وصّل آيفون أولاً", tryAgain:"حاول مرة ثانية", failed:"صار خطأ",
 doneTitle:"تم تثبيت Mirsa", doneSub:"خطوة أخيرة: افتح Mirsa على الآيفون أولاً، بعدين اضغط الزر لإنهاء تسجيل الدخول الآمن.", finishBtn:"فتحت Mirsa، أنهِ التسجيل",
 pairWarn:"حساس: هذا الملف يعطي وصولاً لآيفونك. خليه محلي ولا تشاركه.", setupDone:"اكتمل الإعداد", waiting:"بانتظار Mirsa على الآيفون...", rejected:"Mirsa رفض الطلب. افتح Mirsa وحاول مرة ثانية.", timeout:"Mirsa ما أكّد بالوقت. خلي Mirsa مفتوح على الآيفون واضغط الزر مرة ثانية.", certTitle:"وصلت حد الشهادات", certSub:"اختر الشهادات للإلغاء. ما يُلغى شي بدون اختيارك.", s_pairing:"الاقتران",
 privacy:"كلمة السر تُستخدم مرة واحدة للدخول ولا تُحفظ أبداً.", demo:"معاينة المتصفح بدون الجهاز", lang:"English", done:"تم",
};
export const dict = { en, ar };
export type Key = keyof typeof en;
