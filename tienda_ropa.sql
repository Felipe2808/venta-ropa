-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Servidor: 127.0.0.1
-- Tiempo de generaciÃ³n: 11-11-2026 a las 04:05:21
-- VersiÃ³n del servidor: 10.4.27-MariaDB
-- VersiÃ³n de PHP: 8.2.0

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `tienda_ropa`
--

DELIMITER $$
--
-- Procedimientos
--
CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_admin_cuenta_actual` ()  READS SQL DATA SQL SECURITY INVOKER BEGIN
  SELECT CURRENT_USER() AS cuenta;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_admin_puede_administrar` ()  READS SQL DATA SQL SECURITY INVOKER BEGIN
  DECLARE v_puede BOOLEAN DEFAULT FALSE;
  CALL sp_admin_puede_administrar_cuenta(CURRENT_USER(), v_puede);
  SELECT v_puede AS puede;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_admin_puede_administrar_cuenta` (IN `p_cuenta` VARCHAR(400), OUT `p_puede` BOOLEAN)  READS SQL DATA BEGIN
  SELECT COALESCE(MAX(Create_user_priv = 'Y'), 0) INTO p_puede
  FROM mysql.user
  WHERE CONCAT(User, '@', Host) = p_cuenta;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_admin_usuarios_listar` ()  READS SQL DATA SQL SECURITY INVOKER BEGIN
  SELECT User, Host FROM mysql.user ORDER BY User, Host;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_admin_usuario_crear` (IN `p_usuario` VARCHAR(80), IN `p_host` VARCHAR(255), IN `p_clave` VARCHAR(255), IN `p_rol` VARCHAR(16), IN `p_opciones` VARCHAR(255))  MODIFIES  DATA SQL SECURITY INVOKER BEGIN
  DECLARE v_cuenta VARCHAR(288);
  DECLARE v_privilegios VARCHAR(255) DEFAULT '';
  DECLARE v_puede BOOLEAN DEFAULT FALSE;

  CALL sp_admin_puede_administrar_cuenta(CURRENT_USER(), v_puede);
  IF NOT v_puede THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'La cuenta activa no tiene permiso para administrar usuarios';
  END IF;
  IF p_usuario = '' OR p_usuario NOT REGEXP '^[A-Za-z0-9_]+$' OR p_clave = '' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'El usuario o la contrase¤a no son v lidos';
  END IF;
  IF p_host NOT IN ('localhost', '127.0.0.1', '%') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'El host no es v lido';
  END IF;
  IF p_rol = 'admin' THEN
    SET v_privilegios = 'ALL PRIVILEGES';
  ELSEIF p_rol = 'ventas' THEN
    SET v_privilegios = 'SELECT, INSERT, UPDATE, DELETE';
  ELSEIF p_rol = 'almacen' THEN
    SET v_privilegios = 'SELECT, INSERT, UPDATE';
  ELSEIF p_rol = 'consulta' THEN
    SET v_privilegios = 'SELECT';
  ELSEIF p_rol = 'custom' THEN
    IF p_opciones NOT REGEXP '^(leer|agregar|actualizar|eliminar|crear|borrar|alterar|indice|referencias)(,(leer|agregar|actualizar|eliminar|crear|borrar|alterar|indice|referencias))*$' THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'La lista de privilegios no es v lida';
    END IF;
    IF FIND_IN_SET('leer', p_opciones) > 0 THEN SET v_privilegios = 'SELECT'; END IF;
    IF FIND_IN_SET('agregar', p_opciones) > 0 THEN SET v_privilegios = CONCAT_WS(', ', NULLIF(v_privilegios, ''), 'INSERT'); END IF;
    IF FIND_IN_SET('actualizar', p_opciones) > 0 THEN SET v_privilegios = CONCAT_WS(', ', NULLIF(v_privilegios, ''), 'UPDATE'); END IF;
    IF FIND_IN_SET('eliminar', p_opciones) > 0 THEN SET v_privilegios = CONCAT_WS(', ', NULLIF(v_privilegios, ''), 'DELETE'); END IF;
    IF FIND_IN_SET('crear', p_opciones) > 0 THEN SET v_privilegios = CONCAT_WS(', ', NULLIF(v_privilegios, ''), 'CREATE'); END IF;
    IF FIND_IN_SET('borrar', p_opciones) > 0 THEN SET v_privilegios = CONCAT_WS(', ', NULLIF(v_privilegios, ''), 'DROP'); END IF;
    IF FIND_IN_SET('alterar', p_opciones) > 0 THEN SET v_privilegios = CONCAT_WS(', ', NULLIF(v_privilegios, ''), 'ALTER'); END IF;
    IF FIND_IN_SET('indice', p_opciones) > 0 THEN SET v_privilegios = CONCAT_WS(', ', NULLIF(v_privilegios, ''), 'INDEX'); END IF;
    IF FIND_IN_SET('referencias', p_opciones) > 0 THEN SET v_privilegios = CONCAT_WS(', ', NULLIF(v_privilegios, ''), 'REFERENCES'); END IF;
    IF v_privilegios = '' THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Selecciona al menos un privilegio';
    END IF;
  ELSE
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'El rol no es v lido';
  END IF;

  SET v_cuenta = CONCAT(QUOTE(p_usuario), '@', QUOTE(p_host));
  SET @rutina_admin_sql = CONCAT(
    'CREATE USER IF NOT EXISTS ', v_cuenta,
    ' IDENTIFIED BY ', QUOTE(p_clave)
  );
  PREPARE rutina_admin_stmt FROM @rutina_admin_sql;
  EXECUTE rutina_admin_stmt;
  DEALLOCATE PREPARE rutina_admin_stmt;

  SET @rutina_admin_sql = CONCAT('GRANT EXECUTE ON tienda_ropa.* TO ', v_cuenta);
  PREPARE rutina_admin_stmt FROM @rutina_admin_sql;
  EXECUTE rutina_admin_stmt;
  DEALLOCATE PREPARE rutina_admin_stmt;

  SET @rutina_admin_sql = CONCAT('GRANT ', v_privilegios, ' ON *.* TO ', v_cuenta);
  PREPARE rutina_admin_stmt FROM @rutina_admin_sql;
  EXECUTE rutina_admin_stmt;
  DEALLOCATE PREPARE rutina_admin_stmt;

  SELECT 1 AS ok, CONCAT('Usuario ', p_usuario, ' creado correctamente con los privilegios seleccionados.') AS mensaje;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_admin_usuario_eliminar` (IN `p_usuario` VARCHAR(80), IN `p_host` VARCHAR(255))  MODIFIES  DATA SQL SECURITY INVOKER BEGIN
  DECLARE v_cuenta VARCHAR(400);
  DECLARE v_puede BOOLEAN DEFAULT FALSE;

  CALL sp_admin_puede_administrar_cuenta(CURRENT_USER(), v_puede);
  IF NOT v_puede THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'La cuenta activa no tiene permiso para administrar usuarios';
  END IF;
  IF p_usuario = '' OR p_host = '' OR p_host NOT IN ('localhost', '127.0.0.1', '%') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'La cuenta indicada no es v lida';
  END IF;
  IF CONCAT(p_usuario, '@', p_host) = CURRENT_USER()
     OR LOWER(p_usuario) IN ('root', 'mysql.sys', 'mysql.session', 'mysql.infoschema', 'mariadb.sys') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'No se puede eliminar la cuenta activa ni una cuenta protegida';
  END IF;

  SET v_cuenta = CONCAT(QUOTE(p_usuario), '@', QUOTE(p_host));
  SET @rutina_admin_sql = CONCAT('DROP USER ', v_cuenta);
  PREPARE rutina_admin_stmt FROM @rutina_admin_sql;
  EXECUTE rutina_admin_stmt;
  DEALLOCATE PREPARE rutina_admin_stmt;

  SELECT 1 AS ok, CONCAT('La cuenta ', p_usuario, '@', p_host, ' se elimin¢ correctamente.') AS mensaje;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_inventario_listar` ()  READS SQL DATA SQL SECURITY INVOKER BEGIN
  SELECT p.*, p.stock * p.precio AS valor
  FROM productos AS p
  ORDER BY p.id;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_inventario_reporte` ()  READS SQL DATA SQL SECURITY INVOKER BEGIN
  SELECT sku, nombre, precio, stock, stock * precio AS valor
  FROM productos
  ORDER BY nombre;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_inventario_totales` ()  READS SQL DATA SQL SECURITY INVOKER BEGIN
  SELECT COALESCE(SUM(stock), 0) AS piezas,
         COALESCE(SUM(stock * precio), 0) AS valor
  FROM productos;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_movimientos_recientes` ()  READS SQL DATA SQL SECURITY INVOKER BEGIN
  SELECT m.*, p.nombre, p.sku
  FROM movimientos AS m
  JOIN productos AS p ON p.id = m.producto_id
  ORDER BY m.id DESC
  LIMIT 10;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_movimiento_registrar` (IN `p_sku` VARCHAR(20), IN `p_tipo` VARCHAR(10), IN `p_cantidad` INT)  MODIFIES  DATA SQL SECURITY INVOKER BEGIN
  DECLARE v_encontrado BOOLEAN DEFAULT TRUE;
  DECLARE v_id INT;
  DECLARE v_nombre VARCHAR(80);
  DECLARE v_precio DECIMAL(10,2);
  DECLARE v_stock INT;
  DECLARE v_stock_nuevo INT;
  DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_encontrado = FALSE;

  IF p_tipo NOT IN ('venta', 'entrada') OR p_cantidad < 1 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'El tipo o la cantidad del movimiento no son v lidos';
  END IF;

  SELECT id, nombre, precio, stock INTO v_id, v_nombre, v_precio, v_stock
  FROM productos
  WHERE sku = p_sku
  FOR UPDATE;

  IF NOT v_encontrado THEN
    SELECT 0 AS ok, 'C¢digo no encontrado' AS error;
  ELSEIF p_tipo = 'venta' AND v_stock < p_cantidad THEN
    SELECT 0 AS ok, CONCAT('Solo hay ', v_stock, ' piezas de ', v_nombre) AS error;
  ELSE
    INSERT INTO movimientos (producto_id, tipo, cantidad, precio_unitario, total)
    VALUES (v_id, p_tipo, p_cantidad, v_precio, p_cantidad * v_precio);
    SET v_stock_nuevo = v_stock + IF(p_tipo = 'entrada', p_cantidad, -p_cantidad);
    SELECT 1 AS ok, v_nombre AS nombre, v_stock_nuevo AS stock;
  END IF;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_producto_buscar` (IN `p_sku` VARCHAR(20))  READS SQL DATA SQL SECURITY INVOKER BEGIN
  SELECT * FROM productos WHERE sku = p_sku LIMIT 1;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_producto_crear` (IN `p_prefijo` VARCHAR(3), IN `p_nombre` VARCHAR(80), IN `p_precio` DECIMAL(10,2), IN `p_stock` INT)  MODIFIES  DATA SQL SECURITY INVOKER BEGIN
  DECLARE v_sku VARCHAR(20);
  DECLARE v_producto_id INT;

  CALL sp_siguiente_sku(p_prefijo, v_sku);
  INSERT INTO productos (sku, nombre, precio, stock)
  VALUES (v_sku, p_nombre, p_precio, 0);
  SET v_producto_id = LAST_INSERT_ID();

  IF p_stock > 0 THEN
    INSERT INTO movimientos (producto_id, tipo, cantidad, precio_unitario, total)
    VALUES (v_producto_id, 'entrada', p_stock, p_precio, p_stock * p_precio);
  END IF;

  SELECT 1 AS ok, v_sku AS sku, p_nombre AS nombre;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_producto_editar` (IN `p_sku_anterior` VARCHAR(20), IN `p_prefijo` VARCHAR(3), IN `p_nombre` VARCHAR(80), IN `p_precio` DECIMAL(10,2), IN `p_stock` INT)  MODIFIES  DATA SQL SECURITY INVOKER BEGIN
  DECLARE v_encontrado BOOLEAN DEFAULT TRUE;
  DECLARE v_id INT;
  DECLARE v_sku VARCHAR(20);
  DECLARE v_prefijo_actual VARCHAR(3);
  DECLARE v_sku_nuevo VARCHAR(20);
  DECLARE v_qr_cambio BOOLEAN DEFAULT FALSE;
  DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_encontrado = FALSE;

  SELECT id, sku INTO v_id, v_sku
  FROM productos
  WHERE sku = p_sku_anterior
  FOR UPDATE;

  IF NOT v_encontrado THEN
    SELECT 0 AS ok, 'El producto ya no existe en el inventario' AS error;
  ELSE
    SET v_prefijo_actual = SUBSTRING_INDEX(v_sku, '-', 1);
    SET v_qr_cambio = v_prefijo_actual <> p_prefijo;
    SET v_sku_nuevo = v_sku;
    IF v_qr_cambio THEN
      CALL sp_siguiente_sku(p_prefijo, v_sku_nuevo);
    END IF;

    UPDATE productos
    SET sku = v_sku_nuevo, nombre = p_nombre, precio = p_precio, stock = p_stock
    WHERE id = v_id;

    SELECT 1 AS ok, v_qr_cambio AS qr_cambio, v_sku_nuevo AS sku,
           p_nombre AS nombre, p_precio AS precio, p_stock AS stock,
           p_stock * p_precio AS valor;
  END IF;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_producto_eliminar` (IN `p_sku` VARCHAR(20))  MODIFIES  DATA SQL SECURITY INVOKER BEGIN
  DECLARE v_encontrado BOOLEAN DEFAULT TRUE;
  DECLARE v_id INT;
  DECLARE v_nombre VARCHAR(80);
  DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_encontrado = FALSE;

  SELECT id, nombre INTO v_id, v_nombre
  FROM productos
  WHERE sku = p_sku
  FOR UPDATE;

  IF NOT v_encontrado THEN
    SELECT 0 AS ok, 'El producto ya no existe en el inventario' AS error;
  ELSE
    DELETE FROM movimientos WHERE producto_id = v_id;
    DELETE FROM productos WHERE id = v_id;
    SELECT 1 AS ok, v_nombre AS nombre;
  END IF;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_siguiente_sku` (IN `p_prefijo` VARCHAR(3), OUT `p_sku` VARCHAR(20))  READS SQL DATA SQL SECURITY INVOKER BEGIN
  DECLARE v_fin BOOLEAN DEFAULT FALSE;
  DECLARE v_existente VARCHAR(20);
  DECLARE v_mayor BIGINT DEFAULT 0;
  DECLARE v_siguiente BIGINT;
  DECLARE cur_skus CURSOR FOR
    SELECT sku FROM productos WHERE sku LIKE CONCAT(p_prefijo, '-%') FOR UPDATE;
  DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_fin = TRUE;

  OPEN cur_skus;
  bucle_skus: LOOP
    FETCH cur_skus INTO v_existente;
    IF v_fin THEN
      LEAVE bucle_skus;
    END IF;
    IF v_existente REGEXP CONCAT('^', p_prefijo, '-[0-9]+$') THEN
      SET v_mayor = GREATEST(v_mayor, CAST(SUBSTRING_INDEX(v_existente, '-', -1) AS UNSIGNED));
    END IF;
  END LOOP;
  CLOSE cur_skus;

  SET v_siguiente = v_mayor + 1;
  SET p_sku = CONCAT(p_prefijo, '-', IF(v_siguiente < 1000, LPAD(v_siguiente, 3, '0'), v_siguiente));
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_ventas_hoy` ()  READS SQL DATA SQL SECURITY INVOKER BEGIN
  SELECT COALESCE(SUM(total), 0) AS ventas_hoy
  FROM movimientos
  WHERE tipo = 'venta'
    AND fecha >= CURDATE()
    AND fecha < CURDATE() + INTERVAL 1 DAY;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_ventas_periodo` (IN `p_inicio` DATETIME, IN `p_fin` DATETIME)  READS SQL DATA SQL SECURITY INVOKER BEGIN
  SELECT m.fecha, p.sku, p.nombre, m.cantidad, m.precio_unitario, m.total
  FROM movimientos AS m
  JOIN productos AS p ON p.id = m.producto_id
  WHERE m.tipo = 'venta' AND m.fecha >= p_inicio AND m.fecha < p_fin
  ORDER BY m.fecha DESC, m.id DESC;
END$$

DELIMITER ;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `movimientos`
--

CREATE TABLE `movimientos` (
  `id` int(11) NOT NULL,
  `producto_id` int(11) NOT NULL,
  `tipo` enum('venta','entrada') NOT NULL,
  `cantidad` int(11) NOT NULL,
  `precio_unitario` decimal(10,2) NOT NULL,
  `total` decimal(10,2) NOT NULL,
  `fecha` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `movimientos`
--

INSERT INTO `movimientos` (`id`, `producto_id`, `tipo`, `cantidad`, `precio_unitario`, `total`, `fecha`) VALUES
(34, 1, 'entrada', 1, '90.00', '90.00', '2026-11-11 02:41:22'),
(35, 1, 'entrada', 1, '90.00', '90.00', '2026-11-11 02:41:23'),
(36, 1, 'venta', 1, '90.00', '90.00', '2026-11-11 02:41:26');

--
-- Disparadores `movimientos`
--
DELIMITER $$
CREATE TRIGGER `tr_movimientos_actualizar_stock` AFTER INSERT ON `movimientos` FOR EACH ROW BEGIN
  UPDATE productos
  SET stock = stock + IF(NEW.tipo = 'entrada', NEW.cantidad, -NEW.cantidad)
  WHERE id = NEW.producto_id;
END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `tr_movimientos_validar` BEFORE INSERT ON `movimientos` FOR EACH ROW BEGIN
  DECLARE v_stock INT DEFAULT NULL;
  DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_stock = NULL;

  IF NEW.cantidad < 1 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'La cantidad del movimiento debe ser positiva';
  END IF;

  SELECT stock INTO v_stock
  FROM productos
  WHERE id = NEW.producto_id
  FOR UPDATE;

  IF v_stock IS NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'El producto del movimiento no existe';
  END IF;

  IF NEW.tipo = 'venta' AND v_stock < NEW.cantidad THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'No hay existencias suficientes para la venta';
  END IF;

  SET NEW.total = NEW.cantidad * NEW.precio_unitario;
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `productos`
--

CREATE TABLE `productos` (
  `id` int(11) NOT NULL,
  `sku` varchar(20) NOT NULL,
  `nombre` varchar(80) NOT NULL,
  `precio` decimal(10,2) NOT NULL,
  `stock` int(11) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `productos`
--

INSERT INTO `productos` (`id`, `sku`, `nombre`, `precio`, `stock`) VALUES
(1, 'BLU-001', 'Blusa', '90.00', 1),
(2, 'LEG-001', 'Legging', '90.00', 10),
(3, 'BUF-001', 'Bufanda', '60.00', 1),
(4, 'VES-001', 'Vestido', '90.00', 5),
(10, 'PRO-004', 'Playera Deportiva', '90.00', 1),
(11, 'PRO-001', 'Cardigan', '90.00', 1),
(12, 'PRO-002', 'Sueter', '90.00', 1),
(13, 'PRO-003', 'Pareos', '60.00', 1),
(14, 'PRO-005', 'Top Deportivo', '90.00', 1),
(15, 'PRO-006', 'Sudadera', '90.00', 1),
(16, 'PRO-007', 'Short Deportivo', '90.00', 1);

--
-- Ãndices para tablas volcadas
--

--
-- Indices de la tabla `movimientos`
--
ALTER TABLE `movimientos`
  ADD PRIMARY KEY (`id`),
  ADD KEY `producto_id` (`producto_id`);

--
-- Indices de la tabla `productos`
--
ALTER TABLE `productos`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `sku` (`sku`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `movimientos`
--
ALTER TABLE `movimientos`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=38;

--
-- AUTO_INCREMENT de la tabla `productos`
--
ALTER TABLE `productos`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=18;

--
-- Restricciones para tablas volcadas
--

--
-- Filtros para la tabla `movimientos`
--
ALTER TABLE `movimientos`
  ADD CONSTRAINT `movimientos_ibfk_1` FOREIGN KEY (`producto_id`) REFERENCES `productos` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
