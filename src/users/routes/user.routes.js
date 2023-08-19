const router = require("express").Router();
const validation = require("../../../common/middelWare/validation");
const { logIn, logOut } = require("../controler/login");
const { register, verifyEmail, resendVerificationKey } = require("../controler/register");
const { updateProfile, updatePassword, sendResetKey, resetPassword, changePassword } = require("../controler/update");
const {
    registerSchema,
    verifyEmailSchema,
    resendVerificationKeySchema,
    logInSchema,
    updateProfileSchema,
    updatePasswordSchema,
    resetKeySchema,
    resetPasswordSchema,
    changePasswordSchema,
    logOutSchema
} = require("../validation/user.validation");
const isAuthorized = require("../../../common/middelWare/isAuthorized");
const {
    UPDATE_PROFILE,
    UPDATE_PASSWORD,
    RESET_PASSWORD,
    CHANGE_PASSWORD,
    LOG_OUT
} = require("../endPoint");

const { googleLogin } = require("../controler/googleLogin");

router.post("/register", validation(registerSchema), register);

router.patch("/verifyEmail/:id", validation(verifyEmailSchema), verifyEmail);

router.get("/resendVerificationKey/:id", validation(resendVerificationKeySchema), resendVerificationKey);

router.post("/logIn", validation(logInSchema), logIn);

router.patch("/updateProfile/:id", validation(updateProfileSchema), isAuthorized(UPDATE_PROFILE), updateProfile);

router.patch("/updatePassword/:id", validation(updatePasswordSchema), isAuthorized(UPDATE_PASSWORD), updatePassword);

router.post("/sendResetKey", validation(resetKeySchema), sendResetKey);

router.patch("/resetPassword", validation(resetPasswordSchema), isAuthorized(RESET_PASSWORD), resetPassword);

router.patch("/changePassword/:id", validation(changePasswordSchema), isAuthorized(CHANGE_PASSWORD), changePassword);

router.patch("/logOut/:id", validation(logOutSchema), isAuthorized(LOG_OUT), logOut);

router.post("/googleLogin", googleLogin);




module.exports = router;