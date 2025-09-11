import { useEffect, useState } from "react";
import { useUser } from "@clerk/clerk-react";
import { useNavigate } from "react-router-dom";
import { all_routes } from "../../router/all_routes";

const Validate = () => {
  const { isSignedIn, user } = useUser();
  const routes = all_routes;
  const navigate = useNavigate();
  const [role, setRole] = useState("");
  const [userId, setUserId] = useState("");
  useEffect(() => {
    if (!isSignedIn || !user) {
      navigate(routes.login);
    }
    setRole(user?.publicMetadata?.role || "");
    setUserId(user?.id || "");

    console.log("Hihihi");
    // const publicMetadata = user?.publicMetadata || {};
    // const subdomain = publicMetadata?.subdomain;

    // if (subdomain) {
    //   window.location.href = `http://${subdomain}.localhost:3000/employee-dashboard`;
    // } else {
    //   window.location.href = `http://localhost:3000/employee-dashboard`;
    // }

    switch (role) {
      case "public":
        console.log("public");
        return navigate(routes.login);
        break;
      case "superadmin":
        return navigate(routes.superAdminDashboard);
        break;
      case "admin":
        return navigate(routes.adminDashboard);
        break;
      case "employee":
        return navigate(routes.employeeDashboard);
        break;
      default:
        return navigate(routes.adminDashboard);
        break;
    }

    // Logics for multitenancy system
  }, [isSignedIn, user]);

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: "white",
        zIndex: 9999,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <div className="loader" />
      <style>{`
        .loader {
          border: 6px solid #f3f3f3;
          border-top: 6px solid #3498db;
          border-radius: 50%;
          width: 50px;
          height: 50px;
          animation: spin 1s linear infinite;
        }

        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};

export default Validate;
