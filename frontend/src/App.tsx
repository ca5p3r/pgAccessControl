import { useEffect } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { UNAUTHORIZED_EVENT } from "./api/client";
import { useAuth } from "./api/hooks";
import { Layout } from "./components/Layout";
import { ErrorNote, Spinner } from "./components/ui";
import { ActivityPage } from "./pages/ActivityPage";
import { Dashboard } from "./pages/Dashboard";
import { Login } from "./pages/Login";
import { PermissionsPage } from "./pages/PermissionsPage";
import { ReportsPage } from "./pages/ReportsPage";
import { RoleDetail } from "./pages/RoleDetail";
import { RolesPage } from "./pages/RolesPage";

export default function App() {
  const auth = useAuth();
  const qc = useQueryClient();

  // Any 401 from the API means the session expired: show the login screen again.
  useEffect(() => {
    const h = () => qc.invalidateQueries({ queryKey: ["auth"] });
    window.addEventListener(UNAUTHORIZED_EVENT, h);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, h);
  }, [qc]);

  if (auth.isLoading) return <Spinner label="Starting…" />;
  if (auth.error) return <div className="page"><ErrorNote error={auth.error} retry={() => auth.refetch()} /></div>;
  if (auth.data?.auth_enabled && !auth.data.authenticated) return <Login />;

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="users" element={<RolesPage key="users" kind="user" />} />
        <Route path="users/:name" element={<RoleDetail />} />
        <Route path="roles" element={<RolesPage key="roles" kind="role" />} />
        <Route path="roles/:name" element={<RoleDetail />} />
        <Route path="permissions" element={<PermissionsPage />} />
        <Route path="permissions/:name" element={<PermissionsPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="activity" element={<ActivityPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
