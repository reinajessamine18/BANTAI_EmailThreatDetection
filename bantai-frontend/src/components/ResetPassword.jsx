import { Navigate } from "react-router-dom";

function ResetPassword() {
  return <Navigate to="/forgot-password" replace />;
}

export default ResetPassword;
