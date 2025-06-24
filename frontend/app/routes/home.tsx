import type { Route } from "./+types/home";

// 🔸 디코딩된 유저 정보 타입 정의
type GoogleUser = {
  name: string;
  email: string;
  picture: string;
};

export function meta({}: Route.MetaArgs) {
  return [
    { title: "Gmail Summary Service" },
    { name: "description", content: "Google 계정으로 로그인하세요" },
  ];
}

export default function Home() {
  return (
    <div style={styles.wrapper}>
      <div style={styles.box}>
        <h1 style={styles.title}>Gmail Summary Service</h1>
        <p style={styles.subtitle}>Google 계정으로 간편하게 로그인하세요</p>
        <a href="/auth" style={styles.link}>
          <button style={styles.button}>Google 계정으로 로그인</button>
        </a>
      </div>
    </div>
  );
}

const styles: { [key: string]: React.CSSProperties } = {
  wrapper: {
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    height: "100vh",
    backgroundColor: "#f5f5f5",
    fontFamily: "Inter, sans-serif",
  },
  box: {
    textAlign: "center",
    padding: "2rem",
    borderRadius: "12px",
    backgroundColor: "white",
    boxShadow: "0 4px 20px rgba(0,0,0,0.1)",
    minWidth: "300px",
  },
  title: {
    fontSize: "1.8rem",
    marginBottom: "1rem",
  },
  subtitle: {
    fontSize: "1rem",
    color: "#555",
    marginBottom: "2rem",
  },
  button: {
    backgroundColor: "#4285F4",
    color: "white",
    padding: "12px 20px",
    border: "none",
    borderRadius: "6px",
    fontSize: "1rem",
    cursor: "pointer",
    transition: "background-color 0.3s ease",
  },
  link: {
    textDecoration: "none",
  },
};
