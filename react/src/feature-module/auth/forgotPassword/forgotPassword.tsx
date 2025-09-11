import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { all_routes } from "../../router/all_routes";
import ImageWithBasePath from "../../../core/common/imageWithBasePath";
import { useAuth, useSignIn } from "@clerk/clerk-react";
import { InputOtp } from "primereact/inputotp";
//import { P } from "@clerk/clerk-react/dist/useAuth-y8kzNBhq";

const ForgotPassword = () => {
  const [token, setTokens] = useState<any>();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [successfulCreation, setSuccessfulCreation] = useState(false);
  const [secondFactor, setSecondFactor] = useState(false);
  const [error, setError] = useState("");
  const navigate = useNavigate();
  const [success, setSuccess] = useState(false);
  const { isSignedIn } = useAuth();
  useEffect(() => {
    if (isSignedIn) {
      navigate("/"); // Handle navigation in useEffect  if user aldreasy loggin no forget password
    }
  }, [isSignedIn, navigate]);

  const { isLoaded, signIn, setActive } = useSignIn();

  const [passwordVisibility, setPasswordVisibility] = useState({
    password: false,
    confirmPassword: false,
  });

  const togglePasswordVisibility = (field: "password" | "confirmPassword") => {
    setPasswordVisibility((prevState) => ({
      ...prevState,
      [field]: !prevState[field],
    }));
  };

  const navigation = useNavigate();
  const navigationPath = () => {
    navigation("/");
  };

  const onChangePassword = (password: string) => {
    setPassword(password);
    if (password.match(/^$|\s+/)) {
      setPasswordResponce({
        passwordResponceText:
          "Use 8 or more characters with a mix of letters, numbers & symbols",
        passwordResponceKey: "",
      });
    } else if (password.length === 0) {
      setPasswordResponce({
        passwordResponceText: "",
        passwordResponceKey: "",
      });
    } else if (password.length < 8) {
      setPasswordResponce({
        passwordResponceText: "Weak. Must contain at least 8 characters",
        passwordResponceKey: "0",
      });
    } else if (
      password.search(/[a-z]/) < 0 ||
      password.search(/[A-Z]/) < 0 ||
      password.search(/[0-9]/) < 0
    ) {
      setPasswordResponce({
        passwordResponceText:
          "Average. Must contain at least 1 upper case and number",
        passwordResponceKey: "1",
      });
    } else if (password.search(/(?=.*?[#?!@$%^&*-])/) < 0) {
      setPasswordResponce({
        passwordResponceText: "Almost. Must contain a special symbol",
        passwordResponceKey: "2",
      });
    } else {
      setPasswordResponce({
        passwordResponceText: "Awesome! You have a secure password.",
        passwordResponceKey: "3",
      });
    }
  };

  const [passwordResponce, setPasswordResponce] = useState({
    passwordResponceText:
      "Use 8 or more characters with a mix of letters, numbers, and symbols.",
    passwordResponceKey: "",
  });

  // Move this to the top level

  if (!isLoaded) {
    return null;
  }

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await signIn.create({
        strategy: "reset_password_email_code",
        identifier: email,
      });
      setSuccessfulCreation(true);
      setError("");
    } catch (err: any) {
      console.error("Error:", err.errors[0]?.longMessage);
      setError(err.errors[0]?.longMessage || "An error occurred.");
    }
  };

  const reset = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const result = await signIn.attemptFirstFactor({
        strategy: "reset_password_email_code",
        code,
        password,
      });

      if (result.status === "needs_second_factor") {
        setSecondFactor(true);
        setError("");
      } else if (result.status === "complete") {
        setActive({ session: result.createdSessionId });
        setError("");
        setSuccess(true);
      } else {
        console.log("Result:", result);
      }
    } catch (err: any) {
      console.error("Error:", err.errors[0]?.longMessage);
      setError(err.errors[0]?.longMessage || "An error occurred.");
    }
  };

  // const navigationPath = () => {
  //   navigate(all_routes.resetPasswordSuccess);
  // };

  return (
    <div className="container-fuild">
      <div className="w-100 overflow-hidden position-relative flex-wrap d-block vh-100">
        <div className="row">
          <div className="col-lg-5">
            <div className="login-background position-relative d-lg-flex align-items-center justify-content-center d-none flex-wrap vh-100">
              <div className="bg-overlay-img">
                <ImageWithBasePath
                  src="assets/img/bg/bg-01.png"
                  className="bg-1"
                  alt="Img"
                />
                <ImageWithBasePath
                  src="assets/img/bg/bg-02.png"
                  className="bg-2"
                  alt="Img"
                />
                <ImageWithBasePath
                  src="assets/img/bg/bg-03.png"
                  className="bg-3"
                  alt="Img"
                />
              </div>
              <div className="authentication-card w-100">
                <div className="authen-overlay-item border w-100">
                  <h1 className="text-white display-1">
                    Empowering people <br /> through seamless HR <br />{" "}
                    management.
                  </h1>
                  <div className="my-4 mx-auto authen-overlay-img">
                    <ImageWithBasePath
                      src="assets/img/bg/authentication-bg-01.png"
                      alt="Img"
                    />
                  </div>
                  <div>
                    <p className="text-white fs-20 fw-semibold text-center">
                      Efficiently manage your workforce, streamline <br />{" "}
                      operations effortlessly.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="col-lg-7 col-md-12 col-sm-12">
            <div className="row justify-content-center align-items-center vh-100 overflow-auto flex-wrap">
              <div className="col-md-7 mx-auto vh-100">
                <div className="vh-100 d-flex flex-column justify-content-between p-4 pb-0">
                  <div className=" mx-auto mb-5 text-center">
                    <ImageWithBasePath
                      src="assets/img/logo.svg"
                      className="img-fluid"
                      alt="Logo"
                    />
                  </div>
                  {!success && (
                    <>
                      {!successfulCreation && (
                        <form onSubmit={create}>
                          <div className="">
                            <div className="text-center mb-3">
                              <h2 className="mb-2">Forgot Password?</h2>
                              <p className="mb-0">
                                If you forgot your password, well, then we'll
                                email you instructions to reset your password.
                              </p>
                            </div>
                            <div className="mb-3">
                              <label className="form-label">
                                Email Address
                              </label>
                              <div className="input-group">
                                <input
                                  defaultValue=""
                                  className="form-control border-end-0"
                                  type="email"
                                  placeholder="e.g john@doe.com"
                                  value={email}
                                  onChange={(e) => setEmail(e.target.value)}
                                />
                                <span className="input-group-text border-start-0">
                                  <i className="ti ti-mail" />
                                </span>
                              </div>
                            </div>
                            <div className="mb-3">
                              <button
                                type="submit"
                                className="btn btn-primary w-100"
                              >
                                Reset Password
                              </button>
                            </div>
                            <div className="text-center">
                              <h6 className="fw-normal text-dark mb-0">
                                Return to
                                <Link
                                  to={all_routes.login}
                                  className="hover-a ms-1"
                                >
                                  Sign In
                                </Link>
                              </h6>
                            </div>
                          </div>
                        </form>
                      )}

                      {successfulCreation && (
                        <form onSubmit={reset}>
                          <div className="">
                            <div className="text-center mb-3">
                              <h2 className="mb-2">Reset Password</h2>
                              <p className="mb-0">
                                Your new password must be different from
                                previous used passwords.
                              </p>
                            </div>
                            <div>
                              <div className="input-block mb-3">
                                <div className="mb-3">
                                  <label className="form-label">Password</label>
                                  <div
                                    className="pass-group"
                                    id="passwordInput"
                                  >
                                    <input
                                      type={
                                        passwordVisibility.password
                                          ? "text"
                                          : "password"
                                      }
                                      value={password}
                                      onChange={(e) =>
                                        onChangePassword(e.target.value)
                                      }
                                      className="form-control pass-input"
                                      placeholder="Enter your password"
                                    />
                                    <span
                                      className={`ti toggle-passwords ${
                                        passwordVisibility.password
                                          ? "ti-eye"
                                          : "ti-eye-off"
                                      }`}
                                      onClick={() =>
                                        togglePasswordVisibility("password")
                                      }
                                      style={{ cursor: "pointer" }}
                                    ></span>
                                  </div>
                                </div>
                                <div
                                  className={`password-strength d-flex ${
                                    passwordResponce.passwordResponceKey === "0"
                                      ? "poor-active"
                                      : passwordResponce.passwordResponceKey ===
                                        "1"
                                      ? "avg-active"
                                      : passwordResponce.passwordResponceKey ===
                                        "2"
                                      ? "strong-active"
                                      : passwordResponce.passwordResponceKey ===
                                        "3"
                                      ? "heavy-active"
                                      : ""
                                  }`}
                                  id="passwordStrength"
                                >
                                  <span id="poor" className="active" />
                                  <span id="weak" className="active" />
                                  <span id="strong" className="active" />
                                  <span id="heavy" className="active" />
                                </div>
                              </div>
                              <p className="fs-12">
                                {passwordResponce.passwordResponceText}
                              </p>
                              <div className="mb-3">
                                <div className="mb-3">
                                  <div className="">
                                    <div className="text-center mb-3">
                                      <p className="mb-0">
                                        Please enter the OTP sent to your email
                                        inorder to confirm your account
                                        ownership.
                                      </p>
                                    </div>
                                    <div className="text-center otp-input">
                                      <div className="d-flex justify-content-center align-items-center mb-3">
                                        <InputOtp
                                          value={token}
                                          onChange={(e) => {
                                            setTokens(e.value);
                                            setCode(e?.value?.toString() || "");
                                          }}
                                          integerOnly
                                          length={6}
                                        />
                                      </div>
                                      <div>
                                        <div className="badge bg-danger-transparent mb-3">
                                          <p className="d-flex align-items-center ">
                                            <i className="ti ti-clock me-1" />
                                            09:59
                                          </p>
                                        </div>
                                        {error && (
                                          <p className="text-danger">{error}</p>
                                        )}
                                        <div className="mb-3 d-flex justify-content-center">
                                          <p className="text-gray-9">
                                            Didn't get the OTP?{" "}
                                            <Link
                                              to="/forget-password"
                                              className="text-primary"
                                            >
                                              Resend OTP
                                            </Link>
                                          </p>
                                        </div>
                                      </div>
                                    </div>
                                  </div>
                                </div>
                              </div>
                              <div className="mb-3">
                                <button
                                  type="submit"
                                  className="btn btn-primary w-100"
                                >
                                  Submit
                                </button>
                              </div>
                            </div>
                          </div>
                        </form>
                      )}
                    </>
                  )}

                  {success && (
                    <div className="">
                      <div className="text-center mb-3">
                        <ImageWithBasePath
                          src="assets/img/icons/success-tick.svg"
                          alt="icon"
                          className="img-fluid mb-3"
                        />
                        <h2 className="mb-2">Success</h2>
                        <p className="mb-0">
                          Your new password has been successfully saved
                        </p>
                      </div>
                      <div className="mb-3">
                        <button
                          type="submit"
                          onClick={() => navigationPath()}
                          className="btn btn-primary w-100"
                        >
                          Back to Sign In
                        </button>
                      </div>
                    </div>
                  )}
                  <div className="mt-5 pb-4 text-center">
                    <p className="mb-0 text-gray-9">
                      Copyright © 2025 - Amasqis
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ForgotPassword;
