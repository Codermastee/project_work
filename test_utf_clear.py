file_path = "templates/base.html"

with open(file_path, "rb") as f:
    data = f.read()

cleaned = data.decode("utf-8", "ignore")

with open(file_path, "w", encoding="utf-8") as f:
    f.write(cleaned)

print("success")
######################################
cleaned_lines = []

with open(file_path, "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():          # keep only non-empty lines
            cleaned_lines.append(line)

with open(file_path, "w", encoding="utf-8") as f:
    f.writelines(cleaned_lines)
