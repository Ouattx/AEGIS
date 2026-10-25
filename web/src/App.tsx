import type { ReactNode } from "react";
import { BrowserRouter, Navigate, Route, Routes, useLocation, Link } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import { Layout } from "./components/Layout";
import { TenantStatusProvider } from "./components/status";
import { ToastProvider } from "./components/toast";
import { ActionDetailPage, ActionsPage } from "./pages/Actions";
import { CaseDetailPage } from "./pages/CaseDetail";
import { CasesPage } from "./pages/Cases";
import { FindingsPage } from "./pages/Findings";
import { LedgerPage } from "./pages/Ledger";
import { LoginPage } from "./pages/Login";
import { OverviewPage } from "./pages/Overview";
import { ReportsPage } from "./pages/Reports";
import { SettingsPage } from "./pages/Settings";

function RequireAuth({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const loc = useLocation();
  if (!session) return <Navigate to="/login" replace state={{ from: loc.pathname + loc.search }} />;
  if (!session.me.permissions.includes("read")) {
    return (
      <div className="login">
        <div className="callout warn" style={{ maxWidth: 520 }}>
          <b>This identity cannot use the console.</b> Role(s) {session.me.roles.join(", ")} have no read permission (integration identities may only push telemetry).
        </div>
      </div>
    );
  }
  return <TenantStatusProvider>{children}</TenantStatusProvider>;
}

function NotFound() {
  return (
    <div className="empty">
      <h2>Page not found</h2>
      <p>
        <Link to="/">Back to overview</Link>
      </p>
    </div>
  );
}

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route index element={<OverviewPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="cases" element={<CasesPage />} />
        <Route path="cases/:caseId" element={<CaseDetailPage />} />
        <Route path="actions" element={<ActionsPage />} />
        <Route path="actions/:actionId" element={<ActionDetailPage />} />
        <Route path="ledger" element={<LedgerPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <AppRoutes />
        </BrowserRouter>
      </ToastProvider>
    </AuthProvider>
  );
}
