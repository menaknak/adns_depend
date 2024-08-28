import subprocess

def remove_duplicate_lines(input_file_path):
    output_file_path = input_file_path.replace('.txt', '_unique.txt')

    # 用awk命令去除重复行并保留原有顺序
    command = f"awk '!seen[$0]++' '{input_file_path}' > '{output_file_path}'"

    try:
        # 运行该命令
        subprocess.run(command, shell=True, check=True)
        print(f"去重后的文件已保存至: {output_file_path}")
    except subprocess.CalledProcessError as e:
        print(f"命令执行失败: {e}")

if __name__ == "__main__":
    input_file_path = "/home/nly/DNS/adns_depend/output/error/csv/20240820_logging.txt"
    input_file_path = '/home/nly/DNS/adns_depend/output/error/loop/20240102_logging.txt'
    # input_file_path = '/home/nly/DNS/adns_depend/output/error/loopindataset/20240102_logging.txt'
    input_file_path = '/home/nly/DNS/adns_depend/_multi/output/error/20240824/tranco1M_logging.txt'
    # input_file_path = '/home/nly/DNS/adns_depend/_multi/output/error/20240823/重点域名6766_logging.txt'
    input_file_path = '/home/nly/DNS/adns_depend/_multi/output/error/20240824/wufabreak_logging.txt'
    remove_duplicate_lines(input_file_path)
