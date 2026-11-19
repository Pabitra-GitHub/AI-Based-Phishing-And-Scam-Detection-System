/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: '#2563EB',
          dark: '#1D4ED8',
          light: '#3B82F6',
          50: '#EFF6FF',
          100: '#DBEAFE',
          500: '#3B82F6',
          600: '#2563EB',
          700: '#1D4ED8',
          800: '#1E40AF',
          900: '#1E3A8A',
        },
        brandBg: '#F8FAFC',
        surface: '#FFFFFF',
        brandText: '#0F172A',
        brandMuted: '#64748B',
        brandBorder: '#E2E8F0',
        safe: {
          DEFAULT: '#16A34A',
          light: '#DCFCE7',
          border: '#86EFAC',
          dark: '#15803D'
        },
        suspicious: {
          DEFAULT: '#F59E0B',
          light: '#FEF3C7',
          border: '#FCD34D',
          dark: '#B45309'
        },
        highrisk: {
          DEFAULT: '#F97316',
          light: '#FFEDD5',
          border: '#FDBA74',
          dark: '#C2410C'
        },
        critical: {
          DEFAULT: '#DC2626',
          light: '#FEE2E2',
          border: '#FCA5A5',
          dark: '#991B1B'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      boxShadow: {
        'card': '0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px 0 rgba(0, 0, 0, 0.03)',
        'card-hover': '0 10px 25px -5px rgba(37, 99, 235, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.05)',
        'glow-safe': '0 0 20px -5px rgba(22, 163, 74, 0.4)',
        'glow-danger': '0 0 20px -5px rgba(220, 38, 38, 0.4)',
      }
    },
  },
  plugins: [],
}
