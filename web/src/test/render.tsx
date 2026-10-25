import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AppRoutes } from "../App";
import { AuthProvider } from "../auth/AuthContext";
import { saveSession } from "../auth/session";
import { ToastProvider } from "../components/toast";
import type { Role } from "../api/types";
import { me, token } from "./fixtures";

/** Render the console at ``path``, optionally already signed in as ``role``. */
export function renderApp(path: string, fetchImpl: typeof fetch, role?: Role) {
  if (role) saveSession({ token: token(role), me: me(role) as never, expiresAt: Date.now() + 3600_000 });
  return render(
    <AuthProvider fetchImpl={fetchImpl}>
      <ToastProvider>
        <MemoryRouter initialEntries={[path]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <AppRoutes />
        </MemoryRouter>
      </ToastProvider>
    </AuthProvider>,
  );
}
