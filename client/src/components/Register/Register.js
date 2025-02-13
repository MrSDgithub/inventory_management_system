import React, { useState } from "react";
import axios from "axios";
import { getBaseURL } from "../apiConfig";
import "./Register.scss";

function Register(props) {
  let [email, setEmail] = useState("");
  let [fname, setFname] = useState("");
  let [lname, setLname] = useState("");
  let [pass, setPass] = useState("");
  const [isAdmin, setAdmin] = useState("0");
  const [error, setError] = useState("");

  const handleUserRegistration = async () => {
    if (validateInputs()) {
      const newUser = {
        email,
        password: pass,
        isAdmin,
        fname,
        lname,
      };
  
      const url = `${getBaseURL()}api/users/register`;
  
      try {
        const response = await fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(newUser),
        });
  
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
  
        const data = await response.json();
        console.log("User registered successfully:", data);
  
        if (props?.navigateToLoginPage) {
          props.navigateToLoginPage();
        } else {
          console.warn("navigateToLoginPage function is missing in props.");
        }
      } catch (err) {
        console.error("Error registering user:", err.message);
      }
    } else {
      console.warn("Validation failed. Please check input fields.");
    }
  };
  

  const validateEmail = (email) => {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
  };

  const validatePassword = (password) => {
    return password.length >= 6;
  };

  const validateInputs = () => {
    if (!validateEmail(email)) {
      setError("Please provide a valid email address.");
      return false;
    } else if (fname.trim() === "") {
      setError("Please provide your first name.");
      return false;
    } else if (lname.trim() === "") {
      setError("Please provide your last name.");
      return false;
    } else if (!validatePassword(pass)) {
      setError("Password must be at least 6 characters long.");
      return false;
    }
    setError("");
    return true;
  };

  const updateAdmin = (adminValue) => {
    setAdmin(adminValue);
  };

  return (
    <div className="register-container">
      <h1>Register</h1>
      <div>
        <label>E-Mail</label>
        <input
          type="text"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        ></input>
      </div>
      <div>
        <label>First Name</label>
        <input
          type="text"
          value={fname}
          onChange={(e) => setFname(e.target.value)}
        ></input>
      </div>
      <div>
        <label>Last Name</label>
        <input
          type="text"
          value={lname}
          onChange={(e) => setLname(e.target.value)}
        ></input>
      </div>
      <div>
        <label>Password</label>
        <input
          type="password"
          value={pass}
          onChange={(e) => setPass(e.target.value)}
        ></input>
      </div>
      {error && <div className="error-message">{error}</div>}
      <div className="radio-group">
        <input
          type="radio"
          id="customer"
          name="role"
          value="0"
          checked={isAdmin === "0"}
          onChange={() => updateAdmin("0")}
        />
        <label htmlFor="customer">Customer</label>
        <br />
        <input
          type="radio"
          id="admin"
          name="role"
          value="1"
          checked={isAdmin === "1"}
          onChange={() => updateAdmin("1")}
        />
        <label htmlFor="admin">Admin</label>
      </div>
      <div>
        <button onClick={handleUserRegistration}>Register</button>
      </div>
      <div className="login-link" onClick={() => props.navigateToLoginPage()}>
        Already Logged In User
      </div>
    </div>
  );
}

export default Register;
