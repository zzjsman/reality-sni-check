from pathlib import Path
root = Path(__file__).resolve().parent
source = (root / 'check.py').read_text()
header = '''#!/usr/bin/env bash
set -euo pipefail
command -v python3 >/dev/null || { echo '需要 Python 3（建议 Debian 12 / Ubuntu 22.04 或更新版本）' >&2; exit 1; }
task_dir=$(mktemp -d)
trap 'rm -rf -- "$task_dir"' EXIT
cat > "$task_dir/check.py" <<'REALITY_SNI_PYTHON_EOF'
'''
(root / 'run.sh').write_text(header + source + '\nREALITY_SNI_PYTHON_EOF\npython3 "$task_dir/check.py" "$@"\n')
