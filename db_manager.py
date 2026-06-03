# -*- coding: utf-8 -*-
"""数据库交互式管理工具"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')

def get_tables(conn):
    """获取所有表名"""
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    return [row[0] for row in cursor.fetchall()]

def get_columns(conn, table):
    """获取表的列信息"""
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info([{table}])")
    return [(row[1], row[2]) for row in cursor.fetchall()]

def query_data(conn, table, where=None):
    """查询数据"""
    cursor = conn.cursor()
    sql = f"SELECT * FROM [{table}]"
    if where:
        sql += f" WHERE {where}"
    cursor.execute(sql)
    columns = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()
    return columns, rows

def delete_data(conn, table, where=None):
    """删除数据"""
    cursor = conn.cursor()
    sql = f"DELETE FROM [{table}]"
    if where:
        sql += f" WHERE {where}"
    cursor.execute(sql)
    conn.commit()
    return cursor.rowcount

def print_table(columns, rows):
    """格式化打印表格"""
    if not rows:
        print("  (无数据)")
        return
    
    # 计算每列宽度
    widths = [len(str(col)) for col in columns]
    for row in rows:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(str(val)[:50]))
    
    # 打印表头
    header = " | ".join(str(col).ljust(widths[i]) for i, col in enumerate(columns))
    print(f"  {header}")
    print(f"  {'-' * len(header)}")
    
    # 打印数据行
    for row in rows:
        line = " | ".join(str(val)[:50].ljust(widths[i]) for i, val in enumerate(row))
        print(f"  {line}")

def format_where_clause(where_str):
    """格式化WHERE条件，自动为字符串值添加引号"""
    if not where_str:
        return None
    
    # 处理 字段=值 格式
    if '=' in where_str:
        parts = where_str.split('=', 1)
        field = parts[0].strip()
        value = parts[1].strip()
        
        # 如果值已经被引号包围，直接返回
        if (value.startswith("'") and value.endswith("'")) or \
           (value.startswith('"') and value.endswith('"')):
            return where_str
        
        # 尝试判断是否为数字
        try:
            float(value)
            return f"{field} = {value}"
        except ValueError:
            # 不是数字，添加引号
            return f"{field} = '{value}'"
    
    return where_str

def main():
    if not os.path.exists(DB_PATH):
        print(f"数据库不存在: {DB_PATH}")
        return
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    print("=" * 50)
    print("  数据库管理工具")
    print("=" * 50)
    print(f"  数据库: {DB_PATH}")
    print()
    
    # 获取所有表
    tables = get_tables(conn)
    
    while True:
        print("-" * 50)
        print("操作: 1=查询  2=删除  q=退出")
        action = input("请选择: ").strip().lower()
        
        if action == 'q':
            break
        
        if action not in ('1', '2'):
            print("无效操作，请重新输入")
            continue
        
        # 显示可用表
        print("\n可用表:")
        for i, table in enumerate(tables, 1):
            print(f"  {i}. {table}")
        
        # 选择表
        table_input = input("输入表名 (序号或名称): ").strip()
        if not table_input:
            print("表名不能为空")
            continue
        
        # 支持序号选择
        if table_input.isdigit():
            idx = int(table_input) - 1
            if 0 <= idx < len(tables):
                table_input = tables[idx]
            else:
                print(f"序号无效，范围: 1-{len(tables)}")
                continue
        elif table_input not in tables:
            print(f"表 '{table_input}' 不存在")
            continue
        
        # 显示表结构
        columns = get_columns(conn, table_input)
        print(f"\n表 {table_input} 的字段: {', '.join(f'{name}({type_})' for name, type_ in columns)}")
        
        if action == '1':
            # 查询
            where = input("输入查询条件 (直接回车查询所有): ").strip()
            formatted_where = format_where_clause(where)
            try:
                cols, rows = query_data(conn, table_input, formatted_where)
                print(f"\n查询结果 ({len(rows)} 条):")
                print_table(cols, rows)
            except Exception as e:
                print(f"查询失败: {e}")
        
        elif action == '2':
            # 删除
            where = input("输入删除条件 (格式: 字段=值，直接回车删除所有): ").strip()
            formatted_where = format_where_clause(where)
            
            # 确认删除
            if where:
                confirm = input(f"确认删除 {table_input} 中 {formatted_where} 的数据? (y/n): ").strip().lower()
            else:
                confirm = input(f"确认删除 {table_input} 中所有数据? (y/n): ").strip().lower()
            
            if confirm != 'y':
                print("已取消删除")
                continue
            
            try:
                count = delete_data(conn, table_input, formatted_where)
                print(f"成功删除 {count} 条数据")
            except Exception as e:
                print(f"删除失败: {e}")
        
        print()
    
    conn.close()
    print("已退出")

if __name__ == '__main__':
    main()
